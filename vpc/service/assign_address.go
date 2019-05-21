package service

import (
	"context"
	"net"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (vpcService *vpcService) AssignIP(ctx context.Context, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	if req.SignedAddressAllocation != nil {
		return nil, status.Error(codes.Unimplemented, "Static addresses not yet implemented")
	}

	if req.NetworkInterfaceAttachment.DeviceIndex == 0 {
		return nil, status.Error(codes.InvalidArgument, "Device index 0 not allowed")
	}

	if len(req.RequestedAddresses) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Requested 0 addresses")
	}

	for idx := range req.RequestedAddresses {
		switch family := req.RequestedAddresses[idx].Family; family {
		case titus.Family_FAMILY_V4:
		case titus.Family_FAMILY_V6:
		default:
			return nil, status.Errorf(codes.InvalidArgument, "Requested unsupported address family %q", family.String())
		}
	}

	// TODO: Cache this result
	ec2client := ec2.New(vpcService.session)
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{req.InstanceIdentity.GetInstanceID()}),
	})
	if err != nil {
		log.WithError(err).Error("Received error from AWS during Describe Instances")
		return nil, status.Convert(err).Err()
	}

	if describeInstancesOutput.Reservations == nil || len(describeInstancesOutput.Reservations) == 0 {
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 reservations")
	}
	if describeInstancesOutput.Reservations[0].Instances == nil || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 instances")
	}

	instance := describeInstancesOutput.Reservations[0].Instances[0]

	if int(req.NetworkInterfaceAttachment.DeviceIndex) >= vpc.GetMaxInterfaces(*instance.InstanceType) {
		return nil, status.Error(codes.InvalidArgument, "Interface is out of bounds")
	}

	var iface *ec2.InstanceNetworkInterface
	for idx := range instance.NetworkInterfaces {
		ni := instance.NetworkInterfaces[idx]
		if uint32(*ni.Attachment.DeviceIndex) == req.NetworkInterfaceAttachment.DeviceIndex {
			iface = ni
			break
		}
	}
	// TODO: Make this code less dumb
	if iface == nil {
		return nil, status.Error(codes.NotFound, "Could not find interface for attachment")
	}

	ctx = logger.WithField(ctx, "iface", *iface.NetworkInterfaceId)
	// TODO: Validate these
	wantedSecurityGroups := aws.StringSlice(req.GetSecurityGroupIds())
	// Assign default security groups
	if len(wantedSecurityGroups) == 0 {
		vpcFilter := &ec2.Filter{
			Name:   aws.String("vpc-id"),
			Values: []*string{iface.VpcId},
		}
		groupNameFilter := &ec2.Filter{
			Name:   aws.String("group-name"),
			Values: aws.StringSlice([]string{"default"}),
		}
		describeSecurityGroupsInput := &ec2.DescribeSecurityGroupsInput{
			Filters: []*ec2.Filter{vpcFilter, groupNameFilter},
		}
		// TODO: Cache this
		describeSecurityGroupsOutput, err := ec2client.DescribeSecurityGroupsWithContext(ctx, describeSecurityGroupsInput)
		if err != nil {
			return nil, status.Convert(errors.Wrap(err, "Could not describe security groups")).Err()
		}
		for idx := range describeSecurityGroupsOutput.SecurityGroups {
			sg := describeSecurityGroupsOutput.SecurityGroups[idx]
			wantedSecurityGroups = append(wantedSecurityGroups, sg.GroupId)
		}
	}

	wantedSecurityGroupsSet := set.NewSet()
	for idx := range wantedSecurityGroups {
		wantedSecurityGroupsSet.Add(*wantedSecurityGroups[idx])
	}
	hasSecurityGroupsSet := set.NewSet()
	for idx := range iface.Groups {
		hasSecurityGroupsSet.Add(*iface.Groups[idx].GroupId)
	}

	if !wantedSecurityGroupsSet.Equal(hasSecurityGroupsSet) {
		if !req.AllowSecurityGroupChange {
			return nil, status.Error(codes.FailedPrecondition, "Security group change required, but not allowed")
		}
		logger.G(ctx).WithField("currentSecurityGroups", hasSecurityGroupsSet.ToSlice()).WithField("newSecurityGroups", wantedSecurityGroupsSet.ToSlice()).Info("Changing security groups")
		networkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
			Groups:             wantedSecurityGroups,
			NetworkInterfaceId: iface.NetworkInterfaceId,
		}
		_, err = ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, networkInterfaceAttributeInput)
		if err != nil {
			return nil, status.Convert(errors.Wrap(err, "Cannot modify security groups")).Err()
		}
	}

	return vpcService.assignAddresses(ctx, ec2client, iface, req)
}

func (vpcService *vpcService) assignAddresses(ctx context.Context, ec2client *ec2.EC2, iface *ec2.InstanceNetworkInterface, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
	response := &vpcapi.AssignIPResponse{}
	outstandingRequests := make([]*vpcapi.UsableAddress, len(req.RequestedAddresses))
	for idx := range req.RequestedAddresses {
		requestedAddress := req.RequestedAddresses[idx]
		outstandingRequests[idx] = &vpcapi.UsableAddress{
			Address: &titus.Address{},
		}
		proto.Merge(outstandingRequests[idx].Address, requestedAddress)
	}

	utilizedAddressMap := map[string]*vpcapi.UtilizedAddress{}
	utilizedAddressSet := set.NewSet()
	for idx := range req.UtilizedAddresses {
		canonicalAddress := net.ParseIP(req.UtilizedAddresses[idx].GetAddress().GetAddress())
		utilizedAddressSet.Add(canonicalAddress.String())
		utilizedAddressMap[canonicalAddress.String()] = req.UtilizedAddresses[idx]
	}

	for {
		describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
			NetworkInterfaceIds: []*string{iface.NetworkInterfaceId},
		}

		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
		// TODO: Work around rate limiting here, and do some basic retries
		if err != nil {
			return nil, status.Convert(errors.Wrap(err, "Cannot describe network interfaces")).Err()
		}
		ni := describeNetworkInterfacesOutput.NetworkInterfaces[0]
		response.NetworkInterface = networkInterface(*ni)
		response.SecurityGroupIds = make([]string, len(ni.Groups))
		for idx := range ni.Groups {
			response.SecurityGroupIds[idx] = *ni.Groups[idx].GroupId
		}
		ipv4addresses := set.NewSet()
		ipv6addresses := set.NewSet()
		ipv4addresses.Add(net.ParseIP(*ni.PrivateIpAddress).String())
		for idx := range ni.PrivateIpAddresses {
			pi := ni.PrivateIpAddresses[idx]
			ipv4addresses.Add(net.ParseIP(*pi.PrivateIpAddress).String())
		}
		for idx := range ni.Ipv6Addresses {
			pi := ni.Ipv6Addresses[idx]
			ipv6addresses.Add(net.ParseIP(*pi.Ipv6Address).String())
		}

		entry := logger.G(ctx).WithField("utilizedAddresses", utilizedAddressSet.ToSlice())
		entry.WithField("ipv4addresses", ipv4addresses.ToSlice()).Debug("IPv4 address state")
		entry.WithField("ipv6addresses", ipv6addresses.ToSlice()).Debug("IP64 address state")

		availableIPv4Addresses := ipv4addresses.Difference(utilizedAddressSet)
		availableIPv6Addresses := ipv6addresses.Difference(utilizedAddressSet)

		outstandingV4Needs := 0
		outstandingV6Needs := 0

		logger.G(ctx).WithField("outstandingRequestsCount", len(outstandingRequests)).Debug("Outstanding requests remaining")
		// Let's see if we can fulfill the user's request without any fancy allocations.
		for _, outstandingRequest := range outstandingRequests {
			logger.G(ctx).WithField("outstandingRequests", outstandingRequest).WithField("address", outstandingRequest.Address.Address).Debug("Processing outstanding request")
			if outstandingRequest.Address.Address != "" {
				continue
			}
			// This needs to be assigned. Let's figure out if we can assign from the current IPs on the interface
			if outstandingRequest.Address.Family == titus.Family_FAMILY_V4 {
				if addr := availableIPv4Addresses.Pop(); addr != nil {
					logger.G(ctx).Debugf("Assigned IP %s to interface", addr)
					outstandingRequest.Address.Address = addr.(string)
				} else {
					outstandingV4Needs++
				}
			} else if outstandingRequest.Address.Family == titus.Family_FAMILY_V6 {
				if addr := availableIPv6Addresses.Pop(); addr != nil {
					logger.G(ctx).Debugf("Assigned IP %s to interface", addr)
					outstandingRequest.Address.Address = addr.(string)
				} else {
					outstandingV6Needs++
				}
			} else {
				panic("Unknown family")
			}

		}

		logger.G(ctx).WithField("outstandingV4Needs", outstandingV4Needs).WithField("outstandingV6Needs", outstandingV6Needs).Info("Checked for available addresses")
		if outstandingV4Needs == 0 && outstandingV6Needs == 0 {
			break
		}

		if outstandingV4Needs > 0 {
			assignPrivateIpAddressesInput := &ec2.AssignPrivateIpAddressesInput{
				NetworkInterfaceId: iface.NetworkInterfaceId,
				// TODO: Batch intelligently.
				SecondaryPrivateIpAddressCount: aws.Int64(4),
			}

			if _, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, assignPrivateIpAddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv4 addresses")).Err()
			}
		}
		if outstandingV6Needs > 0 {
			assignIpv6AddressesInput := &ec2.AssignIpv6AddressesInput{
				NetworkInterfaceId: iface.NetworkInterfaceId,
				// TODO: Batch intelligently.
				Ipv6AddressCount: aws.Int64(4),
			}

			if _, err := ec2client.AssignIpv6AddressesWithContext(ctx, assignIpv6AddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
			}
		}
		time.Sleep(time.Second)
	}

	for idx := range outstandingRequests {
		logger.G(ctx).WithField("address", outstandingRequests[idx]).Info("Assigned address")
	}

	response.UsableAddresses = outstandingRequests

	return response, nil
}
