package ec2wrapper

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/session"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/karlseguin/ccache"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	subnetExpirationTime      = 2 * time.Hour
	minInstanceExpirationTime = 45 * time.Minute
	maxInstanceExpirationTime = 75 * time.Minute
)

var (
	getInterfaceMs      = stats.Float64("getInterface.latency", "The time to fetch an Interface", "ns")
	getInterfaceCount   = stats.Int64("getInterface.count", "How many times getInterface was called", "")
	getInterfaceSuccess = stats.Int64("getInterface.success.count", "How many times getInterface succeeded", "")
)

type EC2Session struct {
	Session           *session.Session
	instanceCache     *ccache.Cache
	subnetCache       *ccache.Cache
	batchENIDescriber *BatchENIDescriber
}

func (s *EC2Session) Region(ctx context.Context) (string, error) {
	if s.Session.Config.Region == nil {
		return "us-east-1", nil
	}
	return *s.Session.Config.Region, nil
}

func (s *EC2Session) GetSubnetByID(ctx context.Context, subnetID string) (*ec2.Subnet, error) {
	ctx, span := trace.StartSpan(ctx, "getSubnetbyID")
	defer span.End()

	item, err := s.subnetCache.Fetch(subnetID, subnetExpirationTime, func() (interface{}, error) {
		ec2client := ec2.New(s.Session)
		describeSubnetsOutput, err := ec2client.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: []*string{&subnetID},
		})
		if err != nil {
			logger.G(ctx).WithField("subnetID", subnetID).Error("Could not get Subnet")
			return nil, err
		}

		subnet := describeSubnetsOutput.Subnets[0]
		return subnet, nil
	})
	if err != nil {
		return nil, HandleEC2Error(err, span)
	}

	return item.Value().(*ec2.Subnet), nil
}

func (s *EC2Session) GetNetworkInterfaceByID(ctx context.Context, networkInterfaceID string, deadline time.Duration) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "getNetworkInterface")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("deadline", deadline.String()))
	start := time.Now()

	span.AddAttributes(trace.StringAttribute("eni", networkInterfaceID))
	stats.Record(ctx, getInterfaceCount.M(1))

	networkInterface, err := s.batchENIDescriber.DescribeNetworkInterfacesWithTimeout(ctx, networkInterfaceID, deadline)
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

func (s *EC2Session) GetDefaultSecurityGroups(ctx context.Context, vpcID string) ([]*string, error) {
	// TODO: Cache
	ctx, span := trace.StartSpan(ctx, "getDefaultSecurityGroups")
	defer span.End()
	ec2client := ec2.New(s.Session)

	vpcFilter := &ec2.Filter{
		Name:   aws.String("vpc-id"),
		Values: aws.StringSlice([]string{vpcID}),
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

func (s *EC2Session) ModifySecurityGroups(ctx context.Context, networkInterfaceID string, groupIds []*string) error {
	ctx, span := trace.StartSpan(ctx, "modifySecurityGroups")
	defer span.End()
	ec2client := ec2.New(s.Session)

	groupIds2 := aws.StringValueSlice(groupIds)
	sort.Strings(groupIds2)
	span.AddAttributes(
		trace.StringAttribute("groupIds", fmt.Sprint(groupIds2)),
		trace.StringAttribute("eni", networkInterfaceID),
	)
	networkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             groupIds,
		NetworkInterfaceId: aws.String(networkInterfaceID),
	}
	_, err := ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, networkInterfaceAttributeInput)

	if err != nil {
		return HandleEC2Error(err, span)
	}

	return nil
}

func (s *EC2Session) UnassignPrivateIPAddresses(ctx context.Context, unassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "unassignPrivateIpAddresses")
	defer span.End()
	ec2client := ec2.New(s.Session)
	unassignPrivateIPAddressesOutput, err := ec2client.UnassignPrivateIpAddressesWithContext(ctx, &unassignPrivateIPAddressesInput)
	if err != nil {
		return nil, err
	}
	return unassignPrivateIPAddressesOutput, nil
}

func (s *EC2Session) UnassignIpv6Addresses(ctx context.Context, unassignIpv6AddressesInput ec2.UnassignIpv6AddressesInput) (*ec2.UnassignIpv6AddressesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "UnassignIpv6Addresses")
	defer span.End()
	ec2client := ec2.New(s.Session)
	unassignPrivateIPAddressesOutput, err := ec2client.UnassignIpv6AddressesWithContext(ctx, &unassignIpv6AddressesInput)
	if err != nil {
		return nil, err
	}
	return unassignPrivateIPAddressesOutput, nil
}

func (s *EC2Session) AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "assignPrivateIpAddresses")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("secondaryPrivateIpAddressCount", aws.Int64Value(assignPrivateIPAddressesInput.SecondaryPrivateIpAddressCount)))
	ec2client := ec2.New(s.Session)
	assignPrivateIPAddressesOutput, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, &assignPrivateIPAddressesInput)
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv4 addresses")).Err()
	}

	return assignPrivateIPAddressesOutput, nil
}

func (s *EC2Session) AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "assignIpv6Addresses")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("ipv6AddressCount", aws.Int64Value(assignIpv6AddressesInput.Ipv6AddressCount)))
	ec2client := ec2.New(s.Session)
	assignIpv6AddressesOutput, err := ec2client.AssignIpv6AddressesWithContext(ctx, &assignIpv6AddressesInput)
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
	}

	return assignIpv6AddressesOutput, nil
}

type EC2InstanceCacheValue struct {
	ownerID  string
	instance *ec2.Instance
}

func (s *EC2Session) GetInstance(ctx context.Context, instanceID string, invalidateCache bool) (*ec2.Instance, string, error) {
	ctx, span := trace.StartSpan(ctx, "getInstance")
	defer span.End()
	start := time.Now()
	stats.Record(ctx, getInstanceCount.M(1))

	if invalidateCache {
		stats.Record(ctx, invalidateInstanceFromCache.M(1))
		s.instanceCache.Delete(instanceID)
	}

	stats.Record(ctx, getInstanceFromCache.M(1))
	if item := s.instanceCache.Get(instanceID); item != nil {
		span.AddAttributes(trace.BoolAttribute("cached", true))
		if !item.Expired() {
			span.AddAttributes(trace.BoolAttribute("expired", false))
			stats.Record(ctx, getInstanceFromCacheSuccess.M(1), getInstanceSuccess.M(1))
			val := item.Value().(*EC2InstanceCacheValue)
			return val.instance, val.ownerID, nil
		}
		span.AddAttributes(trace.BoolAttribute("expired", true))
		s.instanceCache.Delete(instanceID)
	} else {
		span.AddAttributes(trace.BoolAttribute("cached", false))
	}

	ec2client := ec2.New(s.Session)
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{instanceID}),
	})

	if err != nil {
		logger.G(ctx).WithError(err).WithField("ec2InstanceId", instanceID).Error("Could not get EC2 Instance")
		return nil, "", HandleEC2Error(err, span)
	}

	if describeInstancesOutput.Reservations == nil || len(describeInstancesOutput.Reservations) == 0 {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: "Describe Instances returned 0 reservations",
		})
		return nil, "", status.Error(codes.NotFound, "Describe Instances returned 0 reservations")
	}
	if describeInstancesOutput.Reservations[0].Instances == nil || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: "Describe Instances returned 0 instances",
		})
		return nil, "", status.Error(codes.NotFound, "Describe Instances returned 0 instances")
	}

	stats.Record(ctx, getInstanceMs.M(float64(time.Since(start).Nanoseconds())), getInstanceSuccess.M(1))
	ret := &EC2InstanceCacheValue{
		ownerID:  aws.StringValue(describeInstancesOutput.Reservations[0].OwnerId),
		instance: describeInstancesOutput.Reservations[0].Instances[0],
	}

	instanceExpirationTime := time.Nanosecond * time.Duration(minInstanceExpirationTime.Nanoseconds()+rand.Int63n(maxInstanceExpirationTime.Nanoseconds()-minInstanceExpirationTime.Nanoseconds()))
	s.instanceCache.Set(instanceID, ret, instanceExpirationTime)

	return ret.instance, ret.ownerID, nil
}
