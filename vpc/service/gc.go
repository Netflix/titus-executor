package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

type utilizedAddress struct {
	lastUsedTime time.Time
}

// currentAddresses are the IPs currently assigned to the ENI
// unallocatedAddressesMap are what were passed from the client
// We do not need the currently allocated addresses, nor the non-viable addresses,
// as at the end of the GC, the machine will take a local recording of the non-viable
// addresses, as well as the currently present addresses. Therefore in a gc cycle, they
// will show up in either the non-viable map, or the unallocated map
func ipsToFree(privateIPAddress string, currentAddresses set.Set, unallocatedAddressesMap map[string]utilizedAddress, gcTimeout time.Duration) set.Set {
	addrsToFreeSet := set.NewSet()
	for addr, utilizedAddressRecord := range unallocatedAddressesMap {
		// This is an IPv6 address, go ahead and ignore it.
		ip := net.ParseIP(addr)
		if ip.To4() == nil {
			continue
		}

		// This is the interface's primary IP address, ignore it.
		if ip.String() == privateIPAddress {
			continue
		}

		// Do not try to free it if we never had it in the first place
		if !currentAddresses.Contains(ip.String()) {
			continue
		}

		// This is an address *that used to be utilized
		// check if was utilized less than a period ago
		// If so, add it to the deletion pile.
		if time.Since(utilizedAddressRecord.lastUsedTime) > gcTimeout {
			addrsToFreeSet.Add(addr)
		}
	}

	return addrsToFreeSet
}

func ifaceIPv4Set(iface *ec2.NetworkInterface) set.Set {
	ipSet := set.NewSet()

	for _, addr := range iface.PrivateIpAddresses {
		addr := net.ParseIP(aws.StringValue(addr.PrivateIpAddress))
		ipSet.Add(addr.String())
	}
	ipSet.Add(net.ParseIP(aws.StringValue((iface.PrivateIpAddress))).String())

	return ipSet
}

func utilizedAddressesToIPSet(ips []*vpcapi.UtilizedAddress) set.Set {
	ipSet := set.NewSet()

	for _, utilizedAddr := range ips {
		addr := net.ParseIP(utilizedAddr.Address.Address)
		ipSet.Add(addr.String())
	}

	return ipSet
}

func utilizedAddressesToIPMap(ips []*vpcapi.UtilizedAddress) (map[string]utilizedAddress, error) {
	ipMap := make(map[string]utilizedAddress, len(ips))
	ipSet := set.NewSet()

	for _, utilizedAddr := range ips {

		ts, err := ptypes.Timestamp(utilizedAddr.LastUsedTime)
		if err != nil {
			return nil, err
		}
		addr := net.ParseIP(utilizedAddr.Address.Address)
		ipMap[addr.String()] = utilizedAddress{lastUsedTime: ts}
		ipSet.Add(addr.String())
	}

	return ipMap, nil
}

func setToStringSlice(s set.Set) []string {
	values := make([]string, s.Cardinality())
	slice := s.ToSlice()
	for idx := range slice {
		values[idx] = slice[idx].(string)
	}

	return values
}

func (vpcService *vpcService) GC(ctx context.Context, req *vpcapi.GCRequest) (*vpcapi.GCResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GC")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"deviceIdx": req.NetworkInterfaceAttachment.DeviceIndex,
		"instance":  req.InstanceIdentity.InstanceID,
	})

	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
		trace.Int64Attribute("deviceIdx", int64(req.NetworkInterfaceAttachment.DeviceIndex)))

	session, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	instance, ownerID, err := session.GetInstance(ctx, req.InstanceIdentity.InstanceID, ec2wrapper.UseCache)
	if err != nil {
		return nil, err
	}

	instanceNetworkInterface, err := ec2wrapper.GetInterfaceByIdxWithRetries(ctx, session, instance, req.NetworkInterfaceAttachment.DeviceIndex)
	if err != nil {
		if ec2wrapper.IsErrInterfaceByIdxNotFound(err) {
			err = status.Errorf(codes.NotFound, err.Error())
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	networkInteface, err := session.GetNetworkInterfaceByID(ctx, aws.StringValue(instanceNetworkInterface.NetworkInterfaceId), 5*time.Second)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if interfaceOwnerID := aws.StringValue(networkInteface.OwnerId); interfaceOwnerID != ownerID {
		region := ec2wrapper.RegionFromAZ(aws.StringValue(instance.Placement.AvailabilityZone))
		session, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: region, AccountID: interfaceOwnerID})
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	return vpcService.gcInterface(ctx, instanceNetworkInterface, session, req, vpcService.gcTimeout)
}

func (vpcService *vpcService) unassignAddresses(ctx context.Context, session *ec2wrapper.EC2Session, networkInterfaceID string, addrsToRemoveSet set.Set, retryAllowed bool) error {
	if addrsToRemoveSet.Cardinality() == 0 {
		return nil
	}

	ctx, span := trace.StartSpan(ctx, "unassignAddresses")
	defer span.End()
	span.AddAttributes(trace.BoolAttribute("retryAllowed", retryAllowed), trace.StringAttribute("addrsToRemove", addrsToRemoveSet.String()))

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	addrsToRemove := setToStringSlice(addrsToRemoveSet)

	rows, err := tx.QueryContext(ctx, "SELECT array_agg(ip_address), home_eni FROM ip_addresses WHERE host(ip_address) = any($1) GROUP BY home_eni", pq.Array(addrsToRemove))
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	// Ugh, I feel bad keeping the txn open so long
	for rows.Next() {
		var eni string
		var staticIPAddresses []string
		err = rows.Scan(pq.Array(&staticIPAddresses), &eni)
		if err != nil {
			return errors.Wrap(err, "Unable to fetch rows from db")
		}
		for idx := range staticIPAddresses {
			addrsToRemoveSet.Remove(staticIPAddresses[idx])
		}

		logger.G(ctx).WithField("staticIPAddresses", staticIPAddresses).WithField("retryAllowed", retryAllowed).WithField("eni", eni).Info("relocating addrs")
		assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
			AllowReassignment:  aws.Bool(true),
			NetworkInterfaceId: aws.String(eni),
			PrivateIpAddresses: aws.StringSlice(staticIPAddresses),
		}

		_, err = session.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput)
		if err != nil {
			return errors.Wrap(err, "Unable to relocate IP addresses")
		}
	}
	_ = tx.Commit()
	// There were only static addresses to remove, neat.
	if addrsToRemoveSet.Cardinality() == 0 {
		return nil
	}

	logger.G(ctx).WithField("addrsToRemove", addrsToRemoveSet.String()).WithField("retryAllowed", retryAllowed).Info("Removing addrs")
	unassignPrivateIPAddressesInput := ec2.UnassignPrivateIpAddressesInput{
		PrivateIpAddresses: aws.StringSlice(setToStringSlice(addrsToRemoveSet)),
		NetworkInterfaceId: aws.String(networkInterfaceID),
	}
	_, err = session.UnassignPrivateIPAddresses(ctx, unassignPrivateIPAddressesInput)
	if err == nil {
		return nil
	}
	awsErr, ok := err.(awserr.Error)
	if !ok {
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	if awsErr.Code() != "InvalidParameterValue" {
		span.SetStatus(traceStatusFromError(awsErr))
		return awsErr
	}

	if !strings.Contains(awsErr.Message(), "Some of the specified addresses are not assigned") {
		span.SetStatus(traceStatusFromError(awsErr))
		return awsErr
	}

	logger.G(ctx).WithError(awsErr).WithField("retryAllowed", retryAllowed).Info("Tried to free too many IPs. Likely due to a stale cache entry")
	if !retryAllowed {
		span.SetStatus(traceStatusFromError(awsErr))
		return awsErr
	}

	iface, err := session.GetNetworkInterfaceByID(ctx, networkInterfaceID, 10*time.Second)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	currentIPv4AddressesSet := ifaceIPv4Set(iface)

	return vpcService.unassignAddresses(ctx, session, networkInterfaceID, currentIPv4AddressesSet.Intersect(addrsToRemoveSet), false)
}

type gcCalculation struct {
	ipsToFreeSet             set.Set
	allocatedAddressesSet    set.Set
	unallocatedAddressesSet  set.Set
	newCurrentIPAddressesSet set.Set
	addressesToDeleteSet     set.Set
	addressesToBumpSet       set.Set
}

func calculateGcInterface(ctx context.Context, iface *ec2.NetworkInterface, req *vpcapi.GCRequest, gcTimeout time.Duration) (*gcCalculation, error) {
	// So now I need to list the IP addresses that are owned by the describeNetworkInterfaces objects, and find those which are
	// not assigned to the interface, and set those to delete.
	//
	// I also need to find addresses which are not in any of the three lists, and set those to bump.

	// currentIPv4AddressSet is the set of IP addresses assigned to the ENI. Since the iface is cached, this may have
	// *fewer* or *more* IP addresses than actually exist.
	ipAddressesCurrentlyAssignedToInterface := ifaceIPv4Set(iface)

	unallocatedAddressesSet := utilizedAddressesToIPSet(req.UnallocatedAddresses)
	unallocatedAddressesMap, err := utilizedAddressesToIPMap(req.UnallocatedAddresses)
	if err != nil {
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	// These are allocated to containers. THEY CANNOT BE DELETED.
	allocatedAddressesSet := utilizedAddressesToIPSet(req.AllocatedAddresses)
	if intersection := allocatedAddressesSet.Intersect(unallocatedAddressesSet); intersection.Cardinality() > 1 {
		err = status.Errorf(codes.InvalidArgument, "The allocated address set (%s), and unallocated set (%s) range overlap", allocatedAddressesSet.String(), unallocatedAddressesSet.String())
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	ipsToFreeSet := ipsToFree(aws.StringValue(iface.PrivateIpAddress), ipAddressesCurrentlyAssignedToInterface, unallocatedAddressesMap, gcTimeout)
	ctx = logger.WithField(ctx, "ipsToFreeSet", ipsToFreeSet.String())
	if (ipsToFreeSet.Intersect(allocatedAddressesSet)).Cardinality() > 0 {
		err = status.Errorf(codes.Internal, "Attempted to free IPs %s, that overlap with allocated set %s", ipsToFreeSet.String(), allocatedAddressesSet.String())
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}
	if ipsToFreeSet.Contains(aws.StringValue(iface.PrivateIpAddress)) {
		err = status.Errorf(codes.Internal, "Attempted to free primary IPs %s, that includes primary IP %s", ipsToFreeSet.String(), aws.StringValue(iface.PrivateIpAddress))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	// newCurrentIPAddressesSet are the IP addresses that are probably assigned to the interface.
	newCurrentIPAddressesSet := ipAddressesCurrentlyAssignedToInterface.Difference(ipsToFreeSet)

	// addressesToDeleteSet are the addresses that the agent knew it had MINUS the new current addresses
	addressesToDeleteSet := ipsToFreeSet.Clone()
	logger.G(ctx).WithField("unallocatedAddressesMap", unallocatedAddressesMap).Debug("unallocatedAddressesMap")
	logger.G(ctx).WithField("ipAddressesCurrentlyAssignedToInterface", ipAddressesCurrentlyAssignedToInterface.String()).Debug("ipAddressesCurrentlyAssignedToInterface")
	for addr := range unallocatedAddressesSet.Iter() {
		ip := net.ParseIP(addr.(string)).String()
		if time.Since(unallocatedAddressesMap[ip].lastUsedTime) < 5*time.Minute {
			continue
		}
		logger.G(ctx).WithField("addr", ip).Debug("Checking if should be deleted")

		// If this IP isn't in the IPs currently assigned to the interface, we can (probably) blow it away
		if !ipAddressesCurrentlyAssignedToInterface.Contains(ip) {
			logger.G(ctx).WithField("addr", ip).Debug("should be deleted")
			addressesToDeleteSet.Add(ip)
		}
	}

	addressesToBumpSet := set.NewSet()
	for addr := range newCurrentIPAddressesSet.Iter() {
		ip := net.ParseIP(addr.(string)).String()
		if allocatedAddressesSet.Contains(ip) {
			continue
		}
		if unallocatedAddressesSet.Contains(ip) {
			continue
		}
		if addressesToDeleteSet.Contains(ip) {
			continue
		}

		addressesToBumpSet.Add(ip)
	}

	return &gcCalculation{
		ipsToFreeSet:             ipsToFreeSet,
		allocatedAddressesSet:    allocatedAddressesSet,
		unallocatedAddressesSet:  unallocatedAddressesSet,
		newCurrentIPAddressesSet: newCurrentIPAddressesSet,
		addressesToDeleteSet:     addressesToDeleteSet,
		addressesToBumpSet:       addressesToBumpSet,
	}, nil
}

func (vpcService *vpcService) gcInterface(ctx context.Context, instanceNetworkInterface *ec2.InstanceNetworkInterface, session *ec2wrapper.EC2Session, req *vpcapi.GCRequest, gcTimeout time.Duration) (*vpcapi.GCResponse, error) {
	ctx, span := trace.StartSpan(ctx, "gcInterface")
	defer span.End()
	iface, err := session.GetNetworkInterfaceByID(ctx, aws.StringValue(instanceNetworkInterface.NetworkInterfaceId), time.Second*10)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(iface.NetworkInterfaceId)))

	gcCalculation, err := calculateGcInterface(ctx, iface, req, gcTimeout)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"allocatedAddressesSet":   gcCalculation.allocatedAddressesSet.String(),
		"unallocatedAddressesSet": gcCalculation.unallocatedAddressesSet.String(),
	})

	err = vpcService.unassignAddresses(ctx, session, aws.StringValue(instanceNetworkInterface.NetworkInterfaceId), gcCalculation.ipsToFreeSet, true)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	// We can get the addresses to delete quite easily. We take the unallocated + nonviable set and subtract the current
	// set.
	resp := vpcapi.GCResponse{}

	span.AddAttributes(trace.StringAttribute("newCurrentIPAddressesSet", gcCalculation.newCurrentIPAddressesSet.String()))
	ctx = logger.WithField(ctx, "newCurrentIPAddressesSet", gcCalculation.newCurrentIPAddressesSet.String())

	span.AddAttributes(trace.StringAttribute("addressesToDeleteSet", gcCalculation.addressesToDeleteSet.String()))
	ctx = logger.WithField(ctx, "addressesToDeleteSet", gcCalculation.addressesToDeleteSet.String())

	span.AddAttributes(trace.StringAttribute("addressesToBumpSet", gcCalculation.addressesToBumpSet.String()))
	ctx = logger.WithField(ctx, "addressesToBumpSet", gcCalculation.addressesToBumpSet.String())

	logger.G(ctx).Info("gc interface result")

	for addrInterface := range gcCalculation.addressesToDeleteSet.Iter() {
		addr := vpcapi.Address{
			Address: addrInterface.(string),
		}
		resp.AddressToDelete = append(resp.AddressToDelete, &addr)
	}

	for addrInterface := range gcCalculation.addressesToBumpSet.Iter() {
		addr := &vpcapi.Address{
			Address: addrInterface.(string),
		}
		resp.AddressToBump = append(resp.AddressToBump, addr)
	}

	return &resp, nil
}

func (vpcService *vpcService) GCV2(ctx context.Context, req *vpcapi.GCRequestV2) (_ *vpcapi.GCResponseV2, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GCV2")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	session, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		// TODO: return error if transaction fails
		if retErr == nil {
			retErr = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(oid::int, branch_enis.id) FROM branch_enis, (SELECT oid FROM pg_class WHERE relname = 'branch_enis') o WHERE branch_eni = $1",
		req.NetworkInterfaceAttachment.Id)
	if err != nil {
		return nil, err
	}

	// TODO: Make this a variable / configurable
	eni, err := session.GetNetworkInterfaceByID(ctx, req.NetworkInterfaceAttachment.Id, 2*time.Second)
	if err != nil {
		err = ec2wrapper.HandleEC2Error(err, span)
		return nil, err
	}

	unallocatedAddresses := sets.NewString()
	allocatedAddresses := sets.NewString()

	for _, addr := range req.AllocatedAddresses {
		allocatedAddresses.Insert(addr.Address)
	}
	for _, addr := range req.UnallocatedAddresses {
		unallocatedAddresses.Insert(addr.Address)
	}

	assignedAddresses := sets.NewString()
	assignedRemovableAddresses := sets.NewString()
	for _, addr := range eni.PrivateIpAddresses {
		ip := net.ParseIP(aws.StringValue(addr.PrivateIpAddress)).String()
		assignedAddresses.Insert(ip)
		if !aws.BoolValue(addr.Primary) {
			assignedRemovableAddresses.Insert(ip)
		}
	}
	for _, addr := range eni.Ipv6Addresses {
		ip := net.ParseIP(aws.StringValue(addr.Ipv6Address)).String()
		assignedAddresses.Insert(ip)
		assignedRemovableAddresses.Insert(ip)
	}

	addressesToDelete := unallocatedAddresses.Difference(assignedAddresses)
	candidates := assignedRemovableAddresses.Difference(allocatedAddresses)

	rows, err := tx.QueryContext(ctx, "SELECT ip_address, home_eni FROM ip_addresses WHERE host(ip_address) = any($1)", pq.Array(assignedRemovableAddresses.List()))
	if err != nil {
		err = errors.Wrap(err, "Could not query database for statically assigned addresses")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	staticAddressesToENI := map[string]string{}
	for rows.Next() {
		var ip string
		var homeEni string
		err = rows.Scan(&ip, &homeEni)
		if err != nil {
			err = errors.Wrap(err, "Could not fetch statically assigned address row")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		ipString := net.ParseIP(ip).String()
		candidates.Delete(ipString)
		staticAddressesToENI[ipString] = homeEni
	}

	err = vpcService.reassignAddresses(ctx, session, staticAddressesToENI)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	timeout := time.Now().Add(-1 * vpcService.gcTimeout)
	logger.G(ctx).WithField("candidates", candidates.List()).WithField("addressesToDelete", addressesToDelete.List()).Debug()
	rows, err = tx.QueryContext(ctx, `SELECT 
  known_ips.ip
FROM 
  (
    SELECT 
      unnest($1::text[]):: inet AS ip
  ) known_ips 
  LEFT JOIN ip_last_used ON known_ips.ip = ip_last_used.ip_address 
WHERE 
  COALESCE(last_used, 'epoch') < $2 
  AND COALESCE(last_allocated, 'epoch') < $2`, pq.Array(candidates.List()), timeout)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not fetch addresses from the database").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	toUnassign := sets.NewString()
	for rows.Next() {
		var ip string
		err = rows.Scan(&ip)
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not read rows from database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		toUnassign.Insert(ip)
		addressesToDelete.Insert(ip)
	}
	logger.G(ctx).WithField("toUnassign", toUnassign.List()).Info("Should unassign")

	err = vpcService.unassignAddressesV2(ctx, tx, session, req.NetworkInterfaceAttachment.Id, toUnassign)
	if err != nil {
		return nil, err
	}

	resp := &vpcapi.GCResponseV2{}
	for _, addr := range addressesToDelete.List() {
		resp.AddressToDelete = append(resp.AddressToDelete, &vpcapi.Address{Address: addr})
	}

	return resp, nil
}

func (vpcService *vpcService) GCSetup(ctx context.Context, req *vpcapi.GCSetupRequest) (*vpcapi.GCSetupResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GCSetup")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	span.AddAttributes(trace.StringAttribute("instance", req.InstanceIdentity.InstanceID))
	session, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	instance, _, err := session.GetInstance(ctx, req.InstanceIdentity.InstanceID, ec2wrapper.UseCache)
	if err != nil {
		return nil, err
	}

	trunkENI := vpcService.getTrunkENI(instance)
	if trunkENI == nil {
		err = status.Error(codes.FailedPrecondition, "Instance does not have trunk ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	resp := &vpcapi.GCSetupResponse{
		NetworkInterfaceAttachment: []*vpcapi.NetworkInterfaceAttachment{},
	}

	// TODO: Replace with query to SQL database
	ec2client := ec2.New(session.Session)

	describeTrunkInterfaceAssociationsInput := &ec2.DescribeTrunkInterfaceAssociationsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("trunk-interface-association.trunk-interface-id"),
				Values: []*string{trunkENI.NetworkInterfaceId},
			},
		},
	}
	for {
		describeTrunkInterfaceAssociationsOutput, err := ec2client.DescribeTrunkInterfaceAssociationsWithContext(ctx, describeTrunkInterfaceAssociationsInput)
		if err != nil {
			err = ec2wrapper.HandleEC2Error(err, span)
			return nil, err
		}
		for _, assoc := range describeTrunkInterfaceAssociationsOutput.InterfaceAssociations {
			resp.NetworkInterfaceAttachment = append(resp.NetworkInterfaceAttachment, &vpcapi.NetworkInterfaceAttachment{
				DeviceIndex: uint32(aws.Int64Value(assoc.VlanId)),
				Id:          aws.StringValue(assoc.BranchInterfaceId),
			})
		}

		if describeTrunkInterfaceAssociationsOutput.NextToken == nil {
			return resp, nil
		}
		describeTrunkInterfaceAssociationsInput.NextToken = describeTrunkInterfaceAssociationsOutput.NextToken
	}
}

func (vpcService *vpcService) reassignAddresses(ctx context.Context, session *ec2wrapper.EC2Session, ipToENIMap map[string]string) error {
	for ip, eni := range ipToENIMap {
		assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
			AllowReassignment:  aws.Bool(true),
			NetworkInterfaceId: aws.String(eni),
			PrivateIpAddresses: aws.StringSlice([]string{ip}),
		}

		_, err := session.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput)
		if err != nil {
			awsErr, ok := err.(awserr.Error)
			if ok && awsErr.Code() == "InvalidParameterValue" {
				continue
			}
			return errors.Wrap(err, "Unable to relocate IP addresses")
		}
	}

	return nil
}

func (vpcService *vpcService) unassignAddressesV2(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, networkInterfaceID string, addrsToRemoveSet sets.String) error {
	if addrsToRemoveSet.Len() == 0 {
		return nil
	}

	ctx, span := trace.StartSpan(ctx, "unassignAddressesV2")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("addrsToRemove", fmt.Sprint((addrsToRemoveSet.List()))))

	v6addrsToRemoveSet := sets.NewString()
	v4addrsToRemoveSet := sets.NewString()
	for _, addr := range addrsToRemoveSet.List() {
		if net.ParseIP(addr).To4() == nil {
			v6addrsToRemoveSet.Insert(addr)
		} else {
			v4addrsToRemoveSet.Insert(addr)
		}
	}

	if v4addrsToRemoveSet.Len() > 0 {
		unassignPrivateIPAddressesInput := ec2.UnassignPrivateIpAddressesInput{
			PrivateIpAddresses: aws.StringSlice(v4addrsToRemoveSet.List()),
			NetworkInterfaceId: aws.String(networkInterfaceID),
		}
		_, err := session.UnassignPrivateIPAddresses(ctx, unassignPrivateIPAddressesInput)
		if err != nil {
			return err
		}
	}

	if v6addrsToRemoveSet.Len() > 0 {
		unassignIpv6AddressesInput := ec2.UnassignIpv6AddressesInput{
			Ipv6Addresses:      aws.StringSlice(v6addrsToRemoveSet.List()),
			NetworkInterfaceId: aws.String(networkInterfaceID),
		}
		_, err := session.UnassignIpv6Addresses(ctx, unassignIpv6AddressesInput)
		if err != nil {
			return err
		}

	}

	return nil
}
