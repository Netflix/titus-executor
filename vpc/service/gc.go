package service

import (
	"context"
	"net"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
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
	// So now I need to list the IP addresses that are owned by the describeNetworkInterfaces objects, and find those which are
	// not assigned to the interface, and set those to delete.
	//
	// I also need to find addresses which are not in any of the three lists, and set those to bump.

	// 1. Check if we have an IP addresses we want to deallocate. Go through the list of unallocated addresses that are in the current addresses pool,
	// and add them to the deallocation list.
	addrsToRemoveSet := set.NewSet()
	for addrInterface := range currentAddresses.Iter() {
		addr := addrInterface.(string)
		utilizedAddr, ok := unallocatedAddressesMap[addr]
		if !ok {
			continue
		}

		if net.ParseIP(addr).To4() == nil {
			continue
		}

		if addr == privateIPAddress {
			continue
		}

		// TODO: Make this adjustable
		if time.Since(utilizedAddr.lastUsedTime) < (2 * time.Minute) {
			continue
		}
		addrsToRemoveSet.Add(addr)
	}

	return addrsToRemoveSet
}

func ifaceIPv4Set(iface *ec2.NetworkInterface) set.Set {
	ipSet := set.NewSet()

	for _, addr := range iface.PrivateIpAddresses {
		addr := net.ParseIP(aws.StringValue(addr.PrivateIpAddress))
		ipSet.Add(addr.String())
	}
	ipSet.Add(aws.StringValue(iface.PrivateIpAddress))

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
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	ctx = logger.WithField(ctx, "deviceIdx", req.NetworkInterfaceAttachment.DeviceIndex)

	ec2instanceSession, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		return nil, err
	}
	instance, err := ec2instanceSession.GetInstance(ctx, ec2wrapper.UseCache)
	if err != nil {
		return nil, err
	}
	instanceIface := ec2wrapper.GetInterfaceByIdx(instance, req.NetworkInterfaceAttachment.DeviceIndex)
	if instanceIface == nil {
		return nil, status.Errorf(codes.NotFound, "Cannot find network interface at attachment index %d", req.NetworkInterfaceAttachment.DeviceIndex)
	}

	ec2NetworkInterfaceSession, err := ec2instanceSession.GetSessionFromNetworkInterface(ctx, instanceIface)
	if err != nil {
		return nil, err
	}

	return gcInterface(ctx, ec2NetworkInterfaceSession, req)
}
func gcInterface(ctx context.Context, ec2NetworkInterfaceSession ec2wrapper.EC2NetworkInterfaceSession, req *vpcapi.GCRequest) (*vpcapi.GCResponse, error) {
	iface, err := ec2NetworkInterfaceSession.GetNetworkInterface(ctx)
	if err != nil {
		return nil, err
	}

	// So now I need to list the IP addresses that are owned by the describeNetworkInterfaces objects, and find those which are
	// not assigned to the interface, and set those to delete.
	//
	// I also need to find addresses which are not in any of the three lists, and set those to bump.
	currentIPv4AddressesSet := ifaceIPv4Set(iface)
	unallocatedAddressesMap, err := utilizedAddressesToIPMap(req.UnallocatedAddresses)
	if err != nil {
		return nil, err
	}
	allocatedAddressesSet := utilizedAddressesToIPSet(req.AllocatedAddresses)
	unallocatedAddressesSet := utilizedAddressesToIPSet(req.UnallocatedAddresses)
	nonviableAddressesSet := utilizedAddressesToIPSet(req.NonviableAddresses)

	addrsToRemoveSet := ipsToFree(aws.StringValue(iface.PrivateIpAddress), currentIPv4AddressesSet, unallocatedAddressesMap)

	if c := addrsToRemoveSet.Cardinality(); c > 0 {
		logger.G(ctx).WithField("addrsToRemove", addrsToRemoveSet.String()).Info("Removing addrs")
		unassignPrivateIPAddressesInput := ec2.UnassignPrivateIpAddressesInput{
			PrivateIpAddresses: aws.StringSlice(setToStringSlice(addrsToRemoveSet)),
		}
		_, err = ec2NetworkInterfaceSession.UnassignPrivateIPAddresses(ctx, unassignPrivateIPAddressesInput)
		if err != nil {
			return nil, err
		}
	}

	// We can get the addresses to delete quite easily. We take the unallocated + nonviable set and subtract the current
	// set.
	resp := vpcapi.GCResponse{}
	// addressesKnownToAgentSet are the addresses that the agent knows it has.
	addressesKnownToAgentSet := unallocatedAddressesSet.Union(nonviableAddressesSet).Union(allocatedAddressesSet)
	// addressesToDeleteSet are the addresses that the agent knew it had MINUS the new current addresses
	newCurrentIPAddressesSet := currentIPv4AddressesSet.Difference(addrsToRemoveSet)
	addressesToDeleteSet := addressesKnownToAgentSet.Difference(newCurrentIPAddressesSet)
	// addressesToBumpSet are addresses that the agent did not know it had, but it still has
	addressesToBumpSet := newCurrentIPAddressesSet.Difference(addressesKnownToAgentSet)
	logger.G(ctx).WithFields(map[string]interface{}{
		"addressesKnownToAgentSet": addressesKnownToAgentSet.String(),
		"newCurrentIPAddressesSet": newCurrentIPAddressesSet.String(),
		"addressesToDeleteSet":     addressesToDeleteSet.String(),
		"addressesToBumpSet":       addressesToBumpSet.String(),
	}).Debug()

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
