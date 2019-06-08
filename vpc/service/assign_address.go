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

	ec2client, instance, err := vpcService.getInstance(ctx, req.InstanceIdentity)
	if err != nil {
		return nil, err
	}

	maxInterfaces, err := vpc.GetMaxInterfaces(*instance.InstanceType)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if int(req.NetworkInterfaceAttachment.DeviceIndex) >= maxInterfaces {
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

	// TODO: Cache
	describeSubnetsOutput, err := ec2client.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{iface.SubnetId},
	})
	if err != nil {
		return nil, err
	}
	subnet := describeSubnetsOutput.Subnets[0]

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

	return assignAddresses(ctx, ec2client, iface, req, subnet, true)
}

func assignAddresses(ctx context.Context, ec2client *ec2.EC2, iface *ec2.InstanceNetworkInterface, req *vpcapi.AssignIPRequest, subnet *ec2.Subnet, allowAssignment bool) (*vpcapi.AssignIPResponse, error) {
	entry := logger.G(ctx).WithField("allowAssignment", allowAssignment)
	response := &vpcapi.AssignIPResponse{}
	utilizedAddressIPv4Set := set.NewSet()
	utilizedAddressIPv6Set := set.NewSet()

	for _, addr := range req.UtilizedAddresses {
		canonicalAddress := net.ParseIP(addr.Address.Address)
		if canonicalAddress.To4() == nil {
			utilizedAddressIPv6Set.Add(canonicalAddress.String())
		} else {
			utilizedAddressIPv4Set.Add(canonicalAddress.String())
		}
	}

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
	assignedIPv4addresses := set.NewSet()
	assignedIPv6addresses := set.NewSet()
	assignedIPv4addresses.Add(net.ParseIP(*ni.PrivateIpAddress).String())
	for idx := range ni.PrivateIpAddresses {
		pi := ni.PrivateIpAddresses[idx]
		assignedIPv4addresses.Add(net.ParseIP(*pi.PrivateIpAddress).String())
	}
	for idx := range ni.Ipv6Addresses {
		pi := ni.Ipv6Addresses[idx]
		assignedIPv6addresses.Add(net.ParseIP(*pi.Ipv6Address).String())
	}

	entry.WithField("ipv4addresses", assignedIPv4addresses.ToSlice()).Debug("assigned IPv4 addresses")
	entry.WithField("ipv6addresses", assignedIPv6addresses.ToSlice()).Debug("assigned IPv6 addresses")
	entry.WithField("ipv4addresses", utilizedAddressIPv4Set.ToSlice()).Debug("utilized IPv4 addresses")
	entry.WithField("ipv6addresses", utilizedAddressIPv6Set.ToSlice()).Debug("utilized IPv6 addresses")

	availableIPv4Addresses := assignedIPv4addresses.Difference(utilizedAddressIPv4Set)
	availableIPv6Addresses := assignedIPv6addresses.Difference(utilizedAddressIPv6Set)

	needIPv4Addresses := availableIPv4Addresses.Cardinality() == 0
	needIPv6Addresses := (req.Ipv6AddressRequested && availableIPv6Addresses.Cardinality() == 0)

	if !needIPv4Addresses && !needIPv6Addresses {
		_, ipnet, err := net.ParseCIDR(*subnet.CidrBlock)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot parse CIDR block")
		}
		prefixlength, _ := ipnet.Mask.Size()
		// TODO: Set a valid prefix length
		for addr := range assignedIPv4addresses.Iter() {
			response.UsableAddresses = append(response.UsableAddresses, &vpcapi.UsableAddress{
				Address:      &titus.Address{Address: addr.(string)},
				PrefixLength: uint32(prefixlength),
			})
		}
		for addr := range assignedIPv6addresses.Iter() {
			response.UsableAddresses = append(response.UsableAddresses, &vpcapi.UsableAddress{
				Address: &titus.Address{Address: addr.(string)},
				// AWS only assigns /128s?
				// This might be a problem for intra-subnet communication? Maybe?
				PrefixLength: uint32(128),
			})
		}
		return response, nil
	}
	entry.WithField("needIPv4Addresses", needIPv4Addresses).WithField("needIPv6Addresses", needIPv6Addresses).Debug("Retrying")

	if allowAssignment {
		if needIPv4Addresses {
			assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
				NetworkInterfaceId: iface.NetworkInterfaceId,
				// TODO: Batch intelligently.
				SecondaryPrivateIpAddressCount: aws.Int64(4),
			}

			if _, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, assignPrivateIPAddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv4 addresses")).Err()
			}
		}

		if needIPv6Addresses {
			assignIpv6AddressesInput := &ec2.AssignIpv6AddressesInput{
				NetworkInterfaceId: iface.NetworkInterfaceId,
				// TODO: Batch intelligently.
				Ipv6AddressCount: aws.Int64(4),
			}

			if _, err := ec2client.AssignIpv6AddressesWithContext(ctx, assignIpv6AddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
			}
		}
	}

	time.Sleep(time.Second)
	return assignAddresses(ctx, ec2client, iface, req, subnet, false)
}
