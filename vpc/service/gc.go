package service

import (
	"context"
	"net"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
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
	_ = ctx

	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
		trace.Int64Attribute("deviceIdx", int64(req.NetworkInterfaceAttachment.DeviceIndex)))

	err := status.Error(codes.Unimplemented, "GC Call is deprecated")
	tracehelpers.SetStatus(err, span)
	return nil, err
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

func (vpcService *vpcService) GCSetupLegacy(ctx context.Context, req *vpcapi.GCLegacySetupRequest) (*vpcapi.GCLegacySetupResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GCSetupLegacy")
	_ = ctx
	defer span.End()

	span.AddAttributes(trace.StringAttribute("instance", req.InstanceIdentity.InstanceID))

	err := status.Error(codes.Unimplemented, "GCSetupLegacy Call is deprecated")
	tracehelpers.SetStatus(err, span)
	return nil, err
}

func (vpcService *vpcService) GCSetup(ctx context.Context, req *vpcapi.GCSetupRequest) (*vpcapi.GCSetupResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GCSetup")
	defer span.End()
	_ = ctx

	span.AddAttributes(trace.StringAttribute("instance", req.InstanceIdentity.InstanceID))

	err := status.Error(codes.Unimplemented, "GCSetup Call is deprecated")
	tracehelpers.SetStatus(err, span)
	return nil, err
}
