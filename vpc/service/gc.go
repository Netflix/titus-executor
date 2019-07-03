package service

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
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
func ipsToFree(privateIPAddress string, currentAddresses set.Set, unallocatedAddressesMap map[string]utilizedAddress) set.Set {
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

		// TODO: Make this adjustable
		// This is an address *that used to be utilized
		// check if was utilized less than 2 minutes ago.
		// If so, add it to the deletion pile.
		if time.Since(utilizedAddressRecord.lastUsedTime) > 2*time.Minute {
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

	ec2instanceSession, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ec2NetworkInterfaceSession, err := ec2instanceSession.GetInterfaceByIdx(ctx, req.NetworkInterfaceAttachment.DeviceIndex)
	if err != nil {
		if ec2wrapper.IsErrInterfaceByIdxNotFound(err) {
			err = status.Errorf(codes.NotFound, err.Error())
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return gcInterface(ctx, ec2NetworkInterfaceSession, req)
}

func unassignAddresses(ctx context.Context, ec2NetworkInterfaceSession ec2wrapper.EC2NetworkInterfaceSession, addrsToRemoveSet set.Set, retryAllowed bool) error {
	if addrsToRemoveSet.Cardinality() == 0 {
		return nil
	}
	ctx, span := trace.StartSpan(ctx, "unassignAddresses")
	defer span.End()
	span.AddAttributes(trace.BoolAttribute("retryAllowed", retryAllowed), trace.StringAttribute("addrsToRemove", addrsToRemoveSet.String()))

	logger.G(ctx).WithField("addrsToRemove", addrsToRemoveSet.String()).WithField("retryAllowed", retryAllowed).Info("Removing addrs")
	unassignPrivateIPAddressesInput := ec2.UnassignPrivateIpAddressesInput{
		PrivateIpAddresses: aws.StringSlice(setToStringSlice(addrsToRemoveSet)),
	}
	_, err := ec2NetworkInterfaceSession.UnassignPrivateIPAddresses(ctx, unassignPrivateIPAddressesInput)
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

	iface, err := ec2NetworkInterfaceSession.GetNetworkInterface(ctx, 10*time.Second)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	currentIPv4AddressesSet := ifaceIPv4Set(iface)

	return unassignAddresses(ctx, ec2NetworkInterfaceSession, currentIPv4AddressesSet.Intersect(addrsToRemoveSet), false)
}

func gcInterface(ctx context.Context, ec2NetworkInterfaceSession ec2wrapper.EC2NetworkInterfaceSession, req *vpcapi.GCRequest) (*vpcapi.GCResponse, error) {
	ctx, span := trace.StartSpan(ctx, "gcInterface")
	defer span.End()
	iface, err := ec2NetworkInterfaceSession.GetNetworkInterface(ctx, time.Second*10)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(iface.NetworkInterfaceId)))

	// So now I need to list the IP addresses that are owned by the describeNetworkInterfaces objects, and find those which are
	// not assigned to the interface, and set those to delete.
	//
	// I also need to find addresses which are not in any of the three lists, and set those to bump.

	// currentIPv4AddressSet is the set of IP addresses assigned to the ENI. Since the iface is cached, this may have
	// *fewer* or *more* IP addresses than actually exist.
	ipAddressesCurrentlyAssignedToInterface := ifaceIPv4Set(iface)

	span.AddAttributes(trace.StringAttribute("ipAddressesCurrentlyAssignedToInterface", ipAddressesCurrentlyAssignedToInterface.String()))
	ctx = logger.WithField(ctx, "ipAddressesCurrentlyAssignedToInterface", ipAddressesCurrentlyAssignedToInterface.String())

	unallocatedAddressesSet := utilizedAddressesToIPSet(req.UnallocatedAddresses)
	span.AddAttributes(trace.StringAttribute("unallocatedAddressesSet", unallocatedAddressesSet.String()))
	ctx = logger.WithField(ctx, "unallocatedAddressesSet", unallocatedAddressesSet.String())
	unallocatedAddressesMap, err := utilizedAddressesToIPMap(req.UnallocatedAddresses)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	// These are allocated to containers. THEY CANNOT BE DELETED.
	allocatedAddressesSet := utilizedAddressesToIPSet(req.AllocatedAddresses)
	span.AddAttributes(trace.StringAttribute("allocatedAddressesSet", allocatedAddressesSet.String()))
	ctx = logger.WithField(ctx, "allocatedAddressesSet", allocatedAddressesSet.String())
	if intersection := allocatedAddressesSet.Intersect(unallocatedAddressesSet); intersection.Cardinality() > 1 {
		err = status.Errorf(codes.InvalidArgument, "The allocated address set (%s), and unallocated set (%s) range overlap", allocatedAddressesSet.String(), unallocatedAddressesSet.String())
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	ipsToFreeSet := ipsToFree(aws.StringValue(iface.PrivateIpAddress), ipAddressesCurrentlyAssignedToInterface, unallocatedAddressesMap)
	span.AddAttributes(trace.StringAttribute("ipsToFreeSet", ipsToFreeSet.String()))
	ctx = logger.WithField(ctx, "ipsToFreeSet", ipsToFreeSet.String())
	if (ipsToFreeSet.Intersect(allocatedAddressesSet)).Cardinality() > 0 {
		err = status.Errorf(codes.Internal, "Attempted to free IPs %s, that overlap with allocated set %s", ipsToFreeSet.String(), allocatedAddressesSet.String())
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}
	if ipsToFreeSet.Contains(aws.StringValue(iface.PrivateIpAddress)) {
		err = status.Errorf(codes.Internal, "Attempted to free primary IPs %s, that includes primary IP %s", ipsToFreeSet.String(), aws.StringValue(iface.PrivateIpAddress))
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	err = unassignAddresses(ctx, ec2NetworkInterfaceSession, ipsToFreeSet, true)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return nil, err
	}

	// We can get the addresses to delete quite easily. We take the unallocated + nonviable set and subtract the current
	// set.
	resp := vpcapi.GCResponse{}
	// newCurrentIPAddressesSet are the IP addresses that are probably assigned to the interface.
	newCurrentIPAddressesSet := ipAddressesCurrentlyAssignedToInterface.Difference(ipsToFreeSet)
	span.AddAttributes(trace.StringAttribute("newCurrentIPAddressesSet", newCurrentIPAddressesSet.String()))
	ctx = logger.WithField(ctx, "newCurrentIPAddressesSet", newCurrentIPAddressesSet.String())

	// addressesToDeleteSet are the addresses that the agent knew it had MINUS the new current addresses
	addressesToDeleteSet := ipsToFreeSet
	for addr := range unallocatedAddressesSet.Iter() {
		ip := net.ParseIP(addr.(string)).String()
		if time.Since(unallocatedAddressesMap[ip].lastUsedTime) < 5*time.Minute {
			continue
		}

		// If this IP isn't in the IPs currently assigned to the interface, we can (probably) blow it away
		if !ipAddressesCurrentlyAssignedToInterface.Contains(ip) {
			addressesToDeleteSet.Add(ip)
		}
	}
	span.AddAttributes(trace.StringAttribute("addressesToDeleteSet", addressesToDeleteSet.String()))
	ctx = logger.WithField(ctx, "addressesToDeleteSet", addressesToDeleteSet.String())

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
	span.AddAttributes(trace.StringAttribute("addressesToBumpSet", addressesToBumpSet.String()))
	ctx = logger.WithField(ctx, "addressesToBumpSet", addressesToBumpSet.String())

	logger.G(ctx).Info("gc interface result")

	for addrInterface := range addressesToDeleteSet.Iter() {
		addr := titus.Address{
			Address: addrInterface.(string),
		}
		resp.AddressToDelete = append(resp.AddressToDelete, &addr)
	}

	for addrInterface := range addressesToBumpSet.Iter() {
		addr := &titus.Address{
			Address: addrInterface.(string),
		}
		resp.AddressToBump = append(resp.AddressToBump, addr)
	}

	return &resp, nil
}
