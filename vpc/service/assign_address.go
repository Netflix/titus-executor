package service

import (
	"context"
	"net"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func isAssignIPRequestValid(req *vpcapi.AssignIPRequest) error {
	if req.SignedAddressAllocation != nil {
		return status.Error(codes.Unimplemented, "Static addresses not yet implemented")
	}

	if req.NetworkInterfaceAttachment.DeviceIndex == 0 {
		return status.Error(codes.InvalidArgument, "Device index 0 not allowed")
	}

	return nil
}

func isAssignIPRequestValidForInstance(req *vpcapi.AssignIPRequest, instance *ec2.Instance) error {
	maxInterfaces, err := vpc.GetMaxInterfaces(*instance.InstanceType)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if int(req.NetworkInterfaceAttachment.DeviceIndex) >= maxInterfaces {
		return status.Error(codes.InvalidArgument, "Interface is out of bounds")
	}

	return nil
}

func (vpcService *vpcService) AssignIP(ctx context.Context, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	if err := isAssignIPRequestValid(req); err != nil {
		return nil, err
	}

	ec2session, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		return nil, err
	}

	instance, err := ec2session.GetInstance(ctx)
	if err != nil {
		return nil, err
	}

	err = isAssignIPRequestValidForInstance(req, instance)
	if err != nil {
		return nil, err
	}

	iface := ec2wrapper.GetInterfaceByIdx(instance, req.NetworkInterfaceAttachment.DeviceIndex)
	if iface == nil {
		return nil, status.Error(codes.NotFound, "Could not find interface for attachment")
	}

	ctx = logger.WithField(ctx, "iface", *iface.NetworkInterfaceId)
	interfaceSession, err := ec2session.GetSessionFromNetworkInterface(ctx, iface)
	if err != nil {
		return nil, err
	}

	subnet, err := interfaceSession.GetSubnet(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: Validate these
	wantedSecurityGroups := aws.StringSlice(req.GetSecurityGroupIds())
	// Assign default security groups
	if len(wantedSecurityGroups) == 0 {
		wantedSecurityGroups, err = interfaceSession.GetDefaultSecurityGroups(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "Could not fetch default security groups")
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
		err = interfaceSession.ModifySecurityGroups(ctx, wantedSecurityGroups)
		if err != nil {
			return nil, err
		}
	}

	return assignAddresses(ctx, interfaceSession, req, subnet, true)
}

func assignAddresses(ctx context.Context, iface ec2wrapper.EC2NetworkInterfaceSession, req *vpcapi.AssignIPRequest, subnet *ec2.Subnet, allowAssignment bool) (*vpcapi.AssignIPResponse, error) {
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

	ni, err := iface.GetNetworkInterface(ctx)
	if err != nil {
		return nil, err
	}
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
			assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
				// TODO: Batch intelligently.
				SecondaryPrivateIpAddressCount: aws.Int64(4),
			}
			if _, err = iface.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput); err != nil {
				return nil, err
			}
		}

		if needIPv6Addresses {
			assignIpv6AddressesInput := ec2.AssignIpv6AddressesInput{
				// TODO: Batch intelligently.
				Ipv6AddressCount: aws.Int64(4),
			}

			if _, err := iface.AssignIPv6Addresses(ctx, assignIpv6AddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
			}
		}
	}

	time.Sleep(time.Second)
	return assignAddresses(ctx, iface, req, subnet, false)
}
