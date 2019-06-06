package service

import (
	"net"
	"time"

	"context"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (vpcService *vpcService) GC(ctx context.Context, req *vpcapi.GCRequest) (*vpcapi.GCResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	ctx = logger.WithField(ctx, "deviceIdx", req.NetworkInterfaceAttachment.DeviceIndex)

	ec2client, instance, err := vpcService.getInstance(ctx, req.InstanceIdentity)
	if err != nil {
		return nil, err
	}
	var ec2iface *ec2.InstanceNetworkInterface
	for idx := range instance.NetworkInterfaces {
		if int(*instance.NetworkInterfaces[idx].Attachment.DeviceIndex) == int(req.NetworkInterfaceAttachment.DeviceIndex) {
			ec2iface = instance.NetworkInterfaces[idx]
			break
		}
	}
	if ec2iface == nil {
		return nil, status.Errorf(codes.NotFound, "Cannot find network interface at attachment index %d", req.NetworkInterfaceAttachment.DeviceIndex)
	}

	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{ec2iface.NetworkInterfaceId},
	}

	describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot describe interfaces from AWS")
	}
	iface := describeNetworkInterfacesOutput.NetworkInterfaces[0]

	// So now I need to list the IP addresses that are owned by the describeNetworkInterfaces objects, and find those which are
	// not assigned to the interface, and set those to delete.
	//
	// I also need to find addresses which are not in any of the three lists, and set those to bump.
	currentAddressesSet := set.NewSet()
	for _, ip := range iface.Ipv6Addresses {
		currentAddressesSet.Add(net.ParseIP(*ip.Ipv6Address).String())
	}
	for _, ip := range iface.PrivateIpAddresses {
		currentAddressesSet.Add(net.ParseIP(*ip.PrivateIpAddress).String())
	}
	currentAddressesSet.Add(net.ParseIP(*iface.PrivateIpAddress).String())

	unallocatedAddressesMap := map[string]time.Time{}
	unallocatedAddressesSet := set.NewSet()
	for _, addr := range req.UnallocatedAddresses {
		ip := net.ParseIP(addr.Address.Address).String()
		unallocatedAddressesSet.Add(ip)
		unallocatedAddressesMap[ip], err = ptypes.Timestamp(addr.LastUsedTime)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	nonviableAddressesMap := map[string]time.Time{}
	nonviableAddressesSet := set.NewSet()
	for _, addr := range req.NonviableAddresses {
		ip := net.ParseIP(addr.Address.Address).String()
		nonviableAddressesSet.Add(ip)
		nonviableAddressesMap[ip], err = ptypes.Timestamp(addr.LastUsedTime)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	allocatedAddressesSet := set.NewSet()
	for _, addr := range req.AllocatedAddresses {
		ip := net.ParseIP(addr.Address.Address).String()
		allocatedAddressesSet.Add(ip)
	}

	// 1. Check if we have an IP addresses we want to deallocate. Go through the list of unallocated addresses that are in the current addresses pool,
	// and add them to the deallocation list.
	newCurrentAddresses := currentAddressesSet.Clone()
	addrsToRemove := set.NewSet()
	for addrInterface := range currentAddressesSet.Iter() {
		addr := addrInterface.(string)
		lastUsedTime, ok := unallocatedAddressesMap[addr]
		if !ok {
			newCurrentAddresses.Add(addr)
			continue
		}
		if net.ParseIP(addr).To4() == nil {
			newCurrentAddresses.Add(addr)
			continue
		}

		if addr == *iface.PrivateIpAddress {
			newCurrentAddresses.Add(addr)
			continue
		}
		// TODO: Make this adjustable
		if time.Since(lastUsedTime) < 2 {
			newCurrentAddresses.Add(addr)
			continue
		}
		addrsToRemove.Add(addr)
	}

	if c := addrsToRemove.Cardinality(); c > 0 {
		addrsToRemoveSlice := make([]string, 0, c)
		for addrInterface := range addrsToRemove.Iter() {
			addrsToRemoveSlice = append(addrsToRemoveSlice, addrInterface.(string))
		}
		logger.G(ctx).WithField("addrsToRemove", addrsToRemove.String()).Info("Removing addrs")
		unassignPrivateIPAddressesInput := &ec2.UnassignPrivateIpAddressesInput{
			NetworkInterfaceId: ec2iface.NetworkInterfaceId,
			PrivateIpAddresses: aws.StringSlice(addrsToRemoveSlice),
		}
		_, err = ec2client.UnassignPrivateIpAddresses(unassignPrivateIPAddressesInput)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to unassign private IP addresses")
		}
	}

	// We can get the addresses to delete quite easily. We take the unallocated + nonviable set and subtract the current
	// set.
	resp := vpcapi.GCResponse{}
	// addressesPresent are the addresses that the agent knows it has
	addressesPresentSet := unallocatedAddressesSet.Clone().Union(nonviableAddressesSet.Clone())
	// addressesToDeleteSet are the addresses that the agent knew it had MINUS the new current addresses
	addressesToDeleteSet := addressesPresentSet.Difference(newCurrentAddresses)
	// addressesToBumpSet are addresses that the agent did not know it had, but it still has
	addressesToBumpSet := newCurrentAddresses.Difference(addressesPresentSet)
	logger.G(ctx).WithFields(map[string]interface{}{
		"addressesPresentSet": addressesPresentSet.String(),
		"newCurrentAddresses": newCurrentAddresses.String(),
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
