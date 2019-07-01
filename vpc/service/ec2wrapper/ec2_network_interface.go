package ec2wrapper

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/status"
)

var (
	keyInterface = tag.MustNewKey("interfaceId")
)

var (
	invalidateInterfaceFromCache = stats.Int64("invalidateInterfaceFromCache.count", "Interface invalidated from cache", "")
	storedInterfaceInCache       = stats.Int64("storeInterfaceInCache.count", "How many times we stored interface in the cache", "")
	getInterfaceFromCache        = stats.Int64("getInterfaceFromCache.count", "How many times getInterface was tried from cache", "")
	getInterfaceFromCacheSuccess = stats.Int64("getInterfaceFromCache.success.count", "How many times getInterface from cache succeeded", "")
	getInterfaceMs               = stats.Float64("getInterface.latency", "The time to fetch an Interface", "ns")
	getInterfaceCount            = stats.Int64("getInterface.count", "How many times getInterface was called", "")
	getInterfaceSuccess          = stats.Int64("getInterface.success.count", "How many times getInterface succeeded", "")
)

type ec2NetworkInterfaceSession struct {
	*ec2BaseSession
	instanceNetworkInterface *ec2.InstanceNetworkInterface
}

type cacheNetworkInterfaceWrapper struct {
	ni      *ec2.NetworkInterface
	fetched time.Time
}

func (s *ec2NetworkInterfaceSession) ElasticNetworkInterfaceID() string {
	return aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId)
}

func (s *ec2NetworkInterfaceSession) GetNetworkInterface(ctx context.Context, strategy CacheStrategy) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "getNetworkInterface")
	defer span.End()
	start := time.Now()
	ec2client := ec2.New(s.session)
	ctx, err := tag.New(ctx, tag.Upsert(keyInterface, aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId)))
	if err != nil {
		return nil, err
	}

	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId)))
	stats.Record(ctx, getInterfaceCount.M(1))
	if strategy&InvalidateCache > 0 {
		stats.Record(ctx, invalidateInterfaceFromCache.M(1))
		span.AddAttributes(trace.BoolAttribute("invalidatecache", true))
		s.interfaceCache.Remove(aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId))
	} else {
		span.AddAttributes(trace.BoolAttribute("invalidatecache", false))
	}
	if strategy&FetchFromCache > 0 {
		span.AddAttributes(trace.BoolAttribute("fetchfromcache", true))

		stats.Record(ctx, getInterfaceFromCache.M(1))
		iface, ok := s.interfaceCache.Get(aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId))
		if ok {
			niw := iface.(*cacheNetworkInterfaceWrapper)
			span.AddAttributes(trace.BoolAttribute("cached", true))
			if time.Since(niw.fetched) < 5*time.Minute {
				stats.Record(ctx, getInterfaceFromCacheSuccess.M(1), getInterfaceSuccess.M(1))
				span.AddAttributes(trace.BoolAttribute("expired", false))
				return niw.ni, nil
			}
			span.AddAttributes(trace.BoolAttribute("expired", true))
		} else {
			span.AddAttributes(trace.BoolAttribute("cached", false))
		}
	} else {
		span.AddAttributes(trace.BoolAttribute("fetchfromcache", false))
	}

	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{s.instanceNetworkInterface.NetworkInterfaceId},
	}

	describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
	// TODO: Work around rate limiting here, and do some basic retries
	if err != nil {
		return nil, handleEC2Error(err, span)
	}

	networkInterface := describeNetworkInterfacesOutput.NetworkInterfaces[0]
	privateIPs := make([]string, len(networkInterface.PrivateIpAddresses)+1)
	for idx := range networkInterface.PrivateIpAddresses {
		privateIPs[idx+1] = aws.StringValue(networkInterface.PrivateIpAddresses[idx].PrivateIpAddress)
	}
	privateIPs[0] = aws.StringValue(networkInterface.PrivateIpAddress)

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

	if strategy&StoreInCache > 0 {
		span.AddAttributes(trace.BoolAttribute("storeincache", true))

		stats.Record(ctx, storedInterfaceInCache.M(1))

		niw := &cacheNetworkInterfaceWrapper{
			ni:      networkInterface,
			fetched: time.Now(),
		}
		s.interfaceCache.Add(aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId), niw)
	} else {
		span.AddAttributes(trace.BoolAttribute("storeincache", false))
	}

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
		trace.StringAttribute("eni", aws.StringValue(s.instanceNetworkInterface.NetworkInterfaceId)),
	)
	networkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             groupIds,
		NetworkInterfaceId: s.instanceNetworkInterface.NetworkInterfaceId,
	}
	_, err := ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, networkInterfaceAttributeInput)

	if err != nil {
		return handleEC2Error(err, span)
	}

	return nil
}

func (s *ec2NetworkInterfaceSession) GetSubnet(ctx context.Context, strategy CacheStrategy) (*ec2.Subnet, error) {
	return s.GetSubnetByID(ctx, aws.StringValue(s.instanceNetworkInterface.SubnetId), strategy)
}

func (s *ec2NetworkInterfaceSession) GetSubnetByID(ctx context.Context, subnetID string, strategy CacheStrategy) (*ec2.Subnet, error) {
	ctx, span := trace.StartSpan(ctx, "getSubnet")
	defer span.End()

	if strategy&InvalidateCache > 0 {
		s.subnetCache.Remove(subnetID)
	}
	if strategy&FetchFromCache > 0 {
		subnet, ok := s.subnetCache.Get(subnetID)
		if ok {
			return subnet.(*ec2.Subnet), nil
		}
	}
	// TODO: Cache
	ec2client := ec2.New(s.session)
	describeSubnetsOutput, err := ec2client.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{&subnetID},
	})
	if err != nil {
		logger.G(ctx).WithField("subnetID", subnetID).Error("Could not get Subnet")
		return nil, handleEC2Error(err, span)
	}

	subnet := describeSubnetsOutput.Subnets[0]
	if strategy&StoreInCache > 0 {
		s.subnetCache.Add(subnetID, subnet)
	}
	return subnet, nil
}

func (s *ec2NetworkInterfaceSession) GetDefaultSecurityGroups(ctx context.Context) ([]*string, error) {
	// TODO: Cache
	ctx, span := trace.StartSpan(ctx, "getDefaultSecurityGroups")
	defer span.End()
	ec2client := ec2.New(s.session)

	vpcFilter := &ec2.Filter{
		Name:   aws.String("vpc-id"),
		Values: []*string{s.instanceNetworkInterface.VpcId},
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
	unassignPrivateIPAddressesInput.NetworkInterfaceId = s.instanceNetworkInterface.NetworkInterfaceId
	ctx, span := trace.StartSpan(ctx, "unassignPrivateIpAddresses")
	defer span.End()
	ec2client := ec2.New(s.session)
	unassignPrivateIPAddressesOutput, err := ec2client.UnassignPrivateIpAddressesWithContext(ctx, &unassignPrivateIPAddressesInput)
	if err != nil {
		return nil, err
	}
	return unassignPrivateIPAddressesOutput, nil
}

func (s *ec2NetworkInterfaceSession) AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error) {
	assignPrivateIPAddressesInput.NetworkInterfaceId = s.instanceNetworkInterface.NetworkInterfaceId
	ctx, span := trace.StartSpan(ctx, "assignPrivateIpAddresses")
	defer span.End()
	ec2client := ec2.New(s.session)
	assignPrivateIPAddressesOutput, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, &assignPrivateIPAddressesInput)
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv4 addresses")).Err()
	}

	return assignPrivateIPAddressesOutput, nil
}

func (s *ec2NetworkInterfaceSession) AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	assignIpv6AddressesInput.NetworkInterfaceId = s.instanceNetworkInterface.NetworkInterfaceId
	ctx, span := trace.StartSpan(ctx, "assignIpv6Addresses")
	defer span.End()
	ec2client := ec2.New(s.session)
	assignIpv6AddressesOutput, err := ec2client.AssignIpv6AddressesWithContext(ctx, &assignIpv6AddressesInput)
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
	}

	return assignIpv6AddressesOutput, nil
}
