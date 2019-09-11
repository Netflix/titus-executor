package ec2wrapper

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/status"
)

var (
	getInterfaceMs      = stats.Float64("getInterface.latency", "The time to fetch an Interface", "ns")
	getInterfaceCount   = stats.Int64("getInterface.count", "How many times getInterface was called", "")
	getInterfaceSuccess = stats.Int64("getInterface.success.count", "How many times getInterface succeeded", "")
)

type networkInterfaceContainer interface {
	networkInterfaceID() string
	subnetID() string
	vpcID() string
}

type ec2NetworkInterfaceSession struct {
	*ec2BaseSession
	networkInterface networkInterfaceContainer
}

func (s *ec2NetworkInterfaceSession) ElasticNetworkInterfaceID() string {
	return s.networkInterface.networkInterfaceID()
}

func (s *ec2NetworkInterfaceSession) Region() string {
	return s.networkInterface.networkInterfaceID()
}

func (s *ec2NetworkInterfaceSession) GetNetworkInterface(ctx context.Context, deadline time.Duration) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "getNetworkInterface")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("deadline", deadline.String()))
	start := time.Now()

	span.AddAttributes(trace.StringAttribute("eni", s.networkInterface.networkInterfaceID()))
	stats.Record(ctx, getInterfaceCount.M(1))

	networkInterface, err := s.batchENIDescriber.DescribeNetworkInterfacesWithTimeout(ctx, s.networkInterface.networkInterfaceID(), deadline)
	// TODO: Work around rate limiting here, and do some basic retries
	if err != nil {
		return nil, HandleEC2Error(err, span)
	}

	privateIPs := make([]string, 1, len(networkInterface.PrivateIpAddresses))
	privateIPs[0] = aws.StringValue(networkInterface.PrivateIpAddress)

	for idx := range networkInterface.PrivateIpAddresses {
		if !aws.BoolValue(networkInterface.PrivateIpAddresses[idx].Primary) {
			privateIPs = append(privateIPs, aws.StringValue(networkInterface.PrivateIpAddresses[idx].PrivateIpAddress))
		}
	}

	ipv6Addresses := make([]string, len(networkInterface.Ipv6Addresses))
	for idx := range networkInterface.Ipv6Addresses {
		ipv6Addresses[idx] = aws.StringValue(networkInterface.Ipv6Addresses[idx].Ipv6Address)
	}

	securityGroupIds := make([]string, len(networkInterface.Groups))
	securityGroupNames := make([]string, len(networkInterface.Groups))

	for idx := range networkInterface.Groups {
		securityGroupIds[idx] = aws.StringValue(networkInterface.Groups[idx].GroupId)
		securityGroupNames[idx] = aws.StringValue(networkInterface.Groups[idx].GroupName)
	}

	sort.Strings(securityGroupIds)
	sort.Strings(securityGroupNames)

	span.AddAttributes(
		trace.StringAttribute("privateIPs", fmt.Sprint(privateIPs)),
		trace.StringAttribute("ipv6Addresses", fmt.Sprint(ipv6Addresses)),
		trace.StringAttribute("securityGroupIds", fmt.Sprint(securityGroupIds)),
		trace.StringAttribute("securityGroupNames", fmt.Sprint(securityGroupNames)),
	)

	stats.Record(ctx, getInterfaceMs.M(float64(time.Since(start).Nanoseconds())), getInterfaceSuccess.M(1))

	return networkInterface, nil
}

func (s *ec2NetworkInterfaceSession) ModifySecurityGroups(ctx context.Context, groupIds []*string) error {
	ctx, span := trace.StartSpan(ctx, "modifySecurityGroups")
	defer span.End()
	ec2client := ec2.New(s.session)

	groupIds2 := aws.StringValueSlice(groupIds)
	sort.Strings(groupIds2)
	span.AddAttributes(
		trace.StringAttribute("groupIds", fmt.Sprint(groupIds2)),
		trace.StringAttribute("eni", s.networkInterface.networkInterfaceID()),
	)
	networkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             groupIds,
		NetworkInterfaceId: aws.String(s.networkInterface.networkInterfaceID()),
	}
	_, err := ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, networkInterfaceAttributeInput)

	if err != nil {
		return HandleEC2Error(err, span)
	}

	return nil
}

func (s *ec2NetworkInterfaceSession) GetSubnet(ctx context.Context, strategy CacheStrategy) (*ec2.Subnet, error) {
	return s.GetSubnetByID(ctx, s.networkInterface.subnetID(), strategy)
}

func (s *ec2NetworkInterfaceSession) GetDefaultSecurityGroups(ctx context.Context) ([]*string, error) {
	// TODO: Cache
	ctx, span := trace.StartSpan(ctx, "getDefaultSecurityGroups")
	defer span.End()
	ec2client := ec2.New(s.session)

	vpcFilter := &ec2.Filter{
		Name:   aws.String("vpc-id"),
		Values: aws.StringSlice([]string{s.networkInterface.vpcID()}),
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

	result := make([]*string, len(describeSecurityGroupsOutput.SecurityGroups))
	for idx := range describeSecurityGroupsOutput.SecurityGroups {
		result[idx] = describeSecurityGroupsOutput.SecurityGroups[idx].GroupId
	}
	return result, nil
}

func (s *ec2NetworkInterfaceSession) UnassignPrivateIPAddresses(ctx context.Context, unassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error) {
	unassignPrivateIPAddressesInput.NetworkInterfaceId = aws.String(s.networkInterface.networkInterfaceID())
	ctx, span := trace.StartSpan(ctx, "unassignPrivateIpAddresses")
	defer span.End()
	ec2client := ec2.New(s.session)
	unassignPrivateIPAddressesOutput, err := ec2client.UnassignPrivateIpAddressesWithContext(ctx, &unassignPrivateIPAddressesInput)
	if err != nil {
		return nil, err
	}
	s.interfaceCache.Remove(s.networkInterface.networkInterfaceID())
	return unassignPrivateIPAddressesOutput, nil
}

func (s *ec2NetworkInterfaceSession) AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error) {
	assignPrivateIPAddressesInput.NetworkInterfaceId = aws.String(s.networkInterface.networkInterfaceID())
	ctx, span := trace.StartSpan(ctx, "assignPrivateIpAddresses")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("secondaryPrivateIpAddressCount", aws.Int64Value(assignPrivateIPAddressesInput.SecondaryPrivateIpAddressCount)))
	ec2client := ec2.New(s.session)
	assignPrivateIPAddressesOutput, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, &assignPrivateIPAddressesInput)
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv4 addresses")).Err()
	}

	return assignPrivateIPAddressesOutput, nil
}

func (s *ec2NetworkInterfaceSession) AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	assignIpv6AddressesInput.NetworkInterfaceId = aws.String(s.networkInterface.networkInterfaceID())
	ctx, span := trace.StartSpan(ctx, "assignIpv6Addresses")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("ipv6AddressCount", aws.Int64Value(assignIpv6AddressesInput.Ipv6AddressCount)))
	ec2client := ec2.New(s.session)
	assignIpv6AddressesOutput, err := ec2client.AssignIpv6AddressesWithContext(ctx, &assignIpv6AddressesInput)
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
	}

	return assignIpv6AddressesOutput, nil
}

type networkInterfaceWrapper struct {
	networkInterface *ec2.NetworkInterface
}

func (ni *networkInterfaceWrapper) networkInterfaceID() string {
	return aws.StringValue(ni.networkInterface.NetworkInterfaceId)
}

func (ni *networkInterfaceWrapper) subnetID() string {
	return aws.StringValue(ni.networkInterface.SubnetId)
}

func (ni *networkInterfaceWrapper) vpcID() string {
	return aws.StringValue(ni.networkInterface.VpcId)
}

type instanceNetworkInterfaceWrapper struct {
	instanceNetworkInterface *ec2.InstanceNetworkInterface
}

func (ni *instanceNetworkInterfaceWrapper) networkInterfaceID() string {
	return aws.StringValue(ni.instanceNetworkInterface.NetworkInterfaceId)
}

func (ni *instanceNetworkInterfaceWrapper) subnetID() string {
	return aws.StringValue(ni.instanceNetworkInterface.SubnetId)
}

func (ni *instanceNetworkInterfaceWrapper) vpcID() string {
	return aws.StringValue(ni.instanceNetworkInterface.VpcId)
}
