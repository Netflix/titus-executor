package service

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
