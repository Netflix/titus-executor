package ec2wrapper

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	ccache "github.com/karlseguin/ccache/v2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/status"
)

const (
	minSubnetExpirationTime   = 90 * time.Minute
	maxSubnetExpirationTime   = 180 * time.Minute
	minInstanceExpirationTime = 45 * time.Minute
	maxInstanceExpirationTime = 75 * time.Minute
)

var (
	getInterfaceMs      = stats.Float64("getInterface.latency", "The time to fetch an Interface", "ns")
	getInterfaceCount   = stats.Int64("getInterface.count", "How many times getInterface was called", "")
	getInterfaceSuccess = stats.Int64("getInterface.success.count", "How many times getInterface succeeded", "")
)

type EC2Session struct {
	Session                 *session.Session
	instanceCache           *ccache.Cache
	subnetCache             *ccache.Cache
	batchENIDescriber       *BatchENIDescriber
	batchInstancesDescriber *BatchInstanceDescriber
	ec2client               *ec2.EC2

	instanceDescriberSingleFlight singleflight.Group

	defaultSecurityGroupSingleFlight singleflight.Group
	defaultSecurityGroupMap          sync.Map
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

	item := s.subnetCache.Get(subnetID)
	if item != nil {
		span.AddAttributes(trace.BoolAttribute("cached", true))
		if !item.Expired() {
			span.AddAttributes(trace.BoolAttribute("expired", false))

			val := item.Value().(*ec2.Subnet)
			return val, nil
		}
		span.AddAttributes(trace.BoolAttribute("expired", true))
	} else {
		span.AddAttributes(trace.BoolAttribute("cached", false))
	}

	ec2client := ec2.New(s.Session)
	describeSubnetsOutput, err := ec2client.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{&subnetID},
	})
	if err != nil {
		logger.G(ctx).WithField("subnetID", subnetID).Error("Could not get Subnet")
		if item != nil {
			span.AddAttributes(trace.BoolAttribute("stale", true))
			return item.Value().(*ec2.Subnet), nil
		}
		return nil, HandleEC2Error(err, span)
	}
	span.AddAttributes(trace.BoolAttribute("stale", false))

	subnet := describeSubnetsOutput.Subnets[0]
	subnetExpirationTime := time.Nanosecond * time.Duration(minSubnetExpirationTime.Nanoseconds()+rand.Int63n(maxSubnetExpirationTime.Nanoseconds()-minSubnetExpirationTime.Nanoseconds())) // nolint: gosec
	s.subnetCache.Set(subnetID, subnet, subnetExpirationTime)
	return subnet, nil
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
	ctx, span := trace.StartSpan(ctx, "GetDefaultSecurityGroups")
	defer span.End()

	val, err, _ := s.defaultSecurityGroupSingleFlight.Do(vpcID, func() (interface{}, error) {
		sg, ok := s.defaultSecurityGroupMap.Load(vpcID)
		if ok {
			return sg, nil
		}

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
			return nil, errors.Wrap(err, "Could not describe security groups")
		}

		if l := len(describeSecurityGroupsOutput.SecurityGroups); l != 1 {
			return nil, fmt.Errorf("Describe call returned unexpected number of security groups: %d", l)
		}

		sgID := aws.StringValue(describeSecurityGroupsOutput.SecurityGroups[0].GroupId)
		s.defaultSecurityGroupMap.Store(vpcID, sgID)

		return sgID, nil
	})

	if err != nil {
		_ = HandleEC2Error(err, span)
		return nil, err
	}

	sg := val.(string)
	return []*string{&sg}, nil
}

// Deprecated
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
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(unassignPrivateIPAddressesInput.NetworkInterfaceId)))
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
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(unassignIpv6AddressesInput.NetworkInterfaceId)))

	ec2client := ec2.New(s.Session)
	unassignPrivateIPAddressesOutput, err := ec2client.UnassignIpv6AddressesWithContext(ctx, &unassignIpv6AddressesInput)
	if err != nil {
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return unassignPrivateIPAddressesOutput, nil
}

func (s *EC2Session) AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "assignPrivateIpAddresses")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(assignPrivateIPAddressesInput.NetworkInterfaceId)))

	span.AddAttributes(trace.Int64Attribute("secondaryPrivateIpAddressCount", aws.Int64Value(assignPrivateIPAddressesInput.SecondaryPrivateIpAddressCount)))
	ec2client := ec2.New(s.Session)
	assignPrivateIPAddressesOutput, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, &assignPrivateIPAddressesInput)
	if err != nil {
		err = errors.Wrap(err, "Cannot assign IPv4 addresses")
		_ = HandleEC2Error(err, span)
		return nil, status.Convert(err).Err()
	}

	return assignPrivateIPAddressesOutput, nil
}

func (s *EC2Session) AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "assignIpv6Addresses")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(assignIpv6AddressesInput.NetworkInterfaceId)))

	span.AddAttributes(trace.Int64Attribute("ipv6AddressCount", aws.Int64Value(assignIpv6AddressesInput.Ipv6AddressCount)))
	ec2client := ec2.New(s.Session)
	assignIpv6AddressesOutput, err := ec2client.AssignIpv6AddressesWithContext(ctx, &assignIpv6AddressesInput)
	if err != nil {
		err = errors.Wrap(err, "Cannot assign IPv6 addresses")
		_ = HandleEC2Error(err, span)
		return nil, status.Convert(err).Err()
	}

	return assignIpv6AddressesOutput, nil
}

func (s *EC2Session) DeleteNetworkInterface(ctx context.Context, input ec2.DeleteNetworkInterfaceInput) (*ec2.DeleteNetworkInterfaceOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DeleteNetworkInterface")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(input.NetworkInterfaceId)))
	ec2client := ec2.New(s.Session)
	output, err := ec2client.DeleteNetworkInterfaceWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot delete network interface")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) CreateNetworkInterface(ctx context.Context, input ec2.CreateNetworkInterfaceInput) (*ec2.CreateNetworkInterfaceOutput, error) {
	ctx, span := trace.StartSpan(ctx, "CreateNetworkInterface")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("subnet", aws.StringValue(input.SubnetId)))
	if input.Groups != nil {
		trace.StringAttribute("securityGroups", fmt.Sprintf("%+v", aws.StringValueSlice(input.Groups)))
	}

	ec2client := ec2.New(s.Session)
	output, err := ec2client.CreateNetworkInterfaceWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot create network interface")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(output.NetworkInterface.NetworkInterfaceId)))
	return output, nil
}

func (s *EC2Session) ModifyNetworkInterfaceAttribute(ctx context.Context, input ec2.ModifyNetworkInterfaceAttributeInput) (*ec2.ModifyNetworkInterfaceAttributeOutput, error) {
	ctx, span := trace.StartSpan(ctx, "ModifyNetworkInterfaceAttribute")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(input.NetworkInterfaceId)))

	if input.SourceDestCheck != nil {
		span.AddAttributes(trace.BoolAttribute("sourceDestCheck", aws.BoolValue(input.SourceDestCheck.Value)))
	} else if input.Groups != nil {
		groups2 := aws.StringValueSlice(input.Groups)
		sort.Strings(groups2)
		span.AddAttributes(trace.StringAttribute("groups", fmt.Sprintf("%v", groups2)))
	} else if input.Description != nil {
		span.AddAttributes(trace.StringAttribute("description", aws.StringValue(input.Description.Value)))
	} else if input.Attachment != nil {
		span.AddAttributes(trace.StringAttribute("attachment", input.Attachment.String()))
	}

	ec2client := ec2.New(s.Session)
	output, err := ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot modify network interface")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) AttachNetworkInterface(ctx context.Context, input ec2.AttachNetworkInterfaceInput) (*ec2.AttachNetworkInterfaceOutput, error) {
	ctx, span := trace.StartSpan(ctx, "AttachNetworkInterface")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("eni", aws.StringValue(input.NetworkInterfaceId)),
		trace.StringAttribute("instance", aws.StringValue(input.InstanceId)),
	)
	ec2client := ec2.New(s.Session)
	output, err := ec2client.AttachNetworkInterfaceWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot attach network interface")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) DescribeNetworkInterfaces(ctx context.Context, input ec2.DescribeNetworkInterfacesInput) (*ec2.DescribeNetworkInterfacesOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DescribeNetworkInterfaces")
	defer span.End()

	// Presumably there are filters here?
	if input.Filters != nil {
		span.AddAttributes(trace.StringAttribute("filters", fmt.Sprintf("%v", input.Filters)))
	}

	ec2client := ec2.New(s.Session)
	output, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot describe network interfaces")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) AssociateTrunkInterface(ctx context.Context, input ec2.AssociateTrunkInterfaceInput) (*ec2.AssociateTrunkInterfaceOutput, error) {
	ctx, span := trace.StartSpan(ctx, "AssociateTrunkInterface")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("trunk", aws.StringValue(input.TrunkInterfaceId)),
		trace.StringAttribute("branch", aws.StringValue(input.BranchInterfaceId)),
		trace.Int64Attribute("idx", aws.Int64Value(input.VlanId)),
	)

	if input.ClientToken != nil {
		span.AddAttributes(trace.StringAttribute("token", aws.StringValue(input.ClientToken)))
	}

	ec2client := ec2.New(s.Session)
	output, err := ec2client.AssociateTrunkInterfaceWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot associate trunk network interface")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) DisassociateTrunkInterface(ctx context.Context, input ec2.DisassociateTrunkInterfaceInput) (*ec2.DisassociateTrunkInterfaceOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DisassociateTrunkInterface")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("associationID", aws.StringValue(input.AssociationId)))
	if input.ClientToken != nil {
		span.AddAttributes(trace.StringAttribute("token", aws.StringValue(input.ClientToken)))
	}

	ec2client := ec2.New(s.Session)
	output, err := ec2client.DisassociateTrunkInterfaceWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot disassociate network interface")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) DescribeTrunkInterfaceAssociations(ctx context.Context, input ec2.DescribeTrunkInterfaceAssociationsInput) (*ec2.DescribeTrunkInterfaceAssociationsOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DescribeTrunkInterfaceAssociations")
	defer span.End()

	if input.Filters != nil {
		span.AddAttributes(trace.StringAttribute("filters", fmt.Sprintf("%v", input.Filters)))
	}

	ec2client := ec2.New(s.Session)
	output, err := ec2client.DescribeTrunkInterfaceAssociationsWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot describe trunk interface associations")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) DisassociateAddress(ctx context.Context, input ec2.DisassociateAddressInput) (*ec2.DisassociateAddressOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DisassociateAddress")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("asssociationID", aws.StringValue(input.AssociationId)))

	ec2client := ec2.New(s.Session)
	output, err := ec2client.DisassociateAddressWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot describe trunk interface associations")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) AssociateAddress(ctx context.Context, input ec2.AssociateAddressInput) (*ec2.AssociateAddressOutput, error) {
	ctx, span := trace.StartSpan(ctx, "AssociateAddress")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("allocationID", aws.StringValue(input.AllocationId)),
		trace.BoolAttribute("allowReassociation", aws.BoolValue(input.AllowReassociation)),
		trace.StringAttribute("eni", aws.StringValue(input.NetworkInterfaceId)),
		trace.StringAttribute("privateIPAddresss", aws.StringValue(input.PrivateIpAddress)),
	)

	ec2client := ec2.New(s.Session)
	output, err := ec2client.AssociateAddressWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot describe trunk interface associations")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) CreateNetworkInterfacePermission(ctx context.Context, input ec2.CreateNetworkInterfacePermissionInput) (*ec2.CreateNetworkInterfacePermissionOutput, error) {
	ctx, span := trace.StartSpan(ctx, "CreateNetworkInterfacePermission")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("accountID", aws.StringValue(input.AwsAccountId)),
		trace.StringAttribute("eni", aws.StringValue(input.NetworkInterfaceId)),
		trace.StringAttribute("permission", aws.StringValue(input.Permission)),
	)

	ec2client := ec2.New(s.Session)
	output, err := ec2client.CreateNetworkInterfacePermissionWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot create network interface permission")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

type EC2InstanceCacheValue struct {
	ownerID  string
	instance *ec2.Instance
}

func (s *EC2Session) GetInstance(ctx context.Context, instanceID string, invalidateCache bool) (*ec2.Instance, string, error) {
	ctx, span := trace.StartSpan(ctx, "getInstance")
	defer span.End()
	stats.Record(ctx, getInstanceCount.M(1))

	if invalidateCache {
		stats.Record(ctx, invalidateInstanceFromCache.M(1))
		s.instanceCache.Delete(instanceID)
	}

	stats.Record(ctx, getInstanceFromCache.M(1))
	if item := s.instanceCache.Get(instanceID); item != nil {
		span.AddAttributes(
			trace.BoolAttribute("cached", true),
			trace.BoolAttribute("expired", item.Expired()),
		)
		stats.Record(ctx, getInstanceFromCacheSuccess.M(1), getInstanceSuccess.M(1))
		val := item.Value().(*EC2InstanceCacheValue)
		if item.Expired() {
			// Repopulate the cache out of band
			go func() {
				_, _, _ = s.instanceDescriberSingleFlight.Do(instanceID, func() (interface{}, error) {
					return s.getInstanceAndStoreInCache(ctx, instanceID)
				})
			}()
		}
		return val.instance, val.ownerID, nil
	}

	span.AddAttributes(trace.BoolAttribute("cached", false))
	val, err, _ := s.instanceDescriberSingleFlight.Do(instanceID, func() (interface{}, error) {
		return s.getInstanceAndStoreInCache(ctx, instanceID)
	})

	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, "", err
	}

	ec2InstanceCacheValue := val.(*EC2InstanceCacheValue)
	return ec2InstanceCacheValue.instance, ec2InstanceCacheValue.ownerID, nil
}

func (s *EC2Session) getInstanceAndStoreInCache(parentCtx context.Context, instanceID string) (*EC2InstanceCacheValue, error) {
	var span *trace.Span
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if parentSpan := trace.FromContext(parentCtx); parentSpan != nil {
		ctx, span = trace.StartSpanWithRemoteParent(ctx, "getInstanceAndStoreInCache", parentSpan.SpanContext())
	} else {
		ctx, span = trace.StartSpan(ctx, "getInstanceAndStoreInCache")
	}
	defer span.End()

	instance, ownerID, err := s.batchInstancesDescriber.DescribeInstanceWithTimeout(ctx, instanceID, 1500*time.Millisecond)
	if err != nil {
		// If it's a not found error, we should consider explicitly deleting it from the cache
		logger.G(ctx).WithError(err).WithField("ec2InstanceId", instanceID).Error("Could not get EC2 Instance")
		return nil, HandleEC2Error(err, span)
	}

	stats.Record(ctx, getInstanceSuccess.M(1))
	ret := &EC2InstanceCacheValue{
		ownerID:  ownerID,
		instance: instance,
	}

	instanceExpirationTime := time.Duration(minInstanceExpirationTime.Nanoseconds() + rand.Int63n(maxInstanceExpirationTime.Nanoseconds()-minInstanceExpirationTime.Nanoseconds())) // nolint: gosec
	s.instanceCache.Set(instanceID, ret, instanceExpirationTime)

	return ret, nil
}

func (s *EC2Session) DescribeSecurityGroups(ctx context.Context, input ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DescribeSecurityGroups")
	defer span.End()

	if input.Filters != nil {
		span.AddAttributes(trace.StringAttribute("filters", fmt.Sprintf("%v", input.Filters)))
	}

	span.AddAttributes(
		trace.StringAttribute("securityGroupsIds", fmt.Sprint(input.GroupIds)),
		trace.StringAttribute("securityGroupsNames", fmt.Sprint(input.GroupNames)),
	)

	ec2client := ec2.New(s.Session)
	output, err := ec2client.DescribeSecurityGroupsWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot describe trunk security groups")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) GetSubnetCidrReservations(ctx context.Context, subnet string) ([]*ec2.SubnetCidrReservation, error) {
	ctx, span := trace.StartSpan(ctx, "GetSubnetCidrReservations")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("subnet", subnet))

	ec2client := ec2.New(s.Session)
	ret := []*ec2.SubnetCidrReservation{}

	input := &ec2.GetSubnetCidrReservationsInput{
		SubnetId: aws.String(subnet),
	}

	for {
		// TODO: Consider filtering based on the reservation description to only fetch titus reserved subnets
		output, err := ec2client.GetSubnetCidrReservationsWithContext(ctx, input)

		if err != nil {
			err = errors.Wrap(err, "Cannot get subnet cidr reservations")
			_ = HandleEC2Error(err, span)
			return nil, err
		}

		ret = append(ret, output.SubnetIpv6CidrReservations...)
		ret = append(ret, output.SubnetIpv4CidrReservations...)
		input.NextToken = output.NextToken
		if input.NextToken == nil {
			break
		}
	}
	return ret, nil
}

func (s *EC2Session) CreateSubnetCidrReservation(ctx context.Context, input ec2.CreateSubnetCidrReservationInput) (*ec2.CreateSubnetCidrReservationOutput, error) {
	ctx, span := trace.StartSpan(ctx, "CreateSubnetCidrReservation")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("cidr", aws.StringValue(input.Cidr)),
		trace.StringAttribute("subnet", aws.StringValue(input.SubnetId)),
		trace.StringAttribute("description", aws.StringValue(input.Description)),
		trace.StringAttribute("type", aws.StringValue(input.ReservationType)),
	)

	ec2client := ec2.New(s.Session)
	output, err := ec2client.CreateSubnetCidrReservationWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot create subnet cidr reservation")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) DeleteSubnetCidrReservation(ctx context.Context, input ec2.DeleteSubnetCidrReservationInput) (*ec2.DeleteSubnetCidrReservationOutput, error) {
	ctx, span := trace.StartSpan(ctx, "DeleteSubnetCidrReservation")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("subnetCidrReservationId", aws.StringValue(input.SubnetCidrReservationId)),
	)

	ec2client := ec2.New(s.Session)
	output, err := ec2client.DeleteSubnetCidrReservationWithContext(ctx, &input)
	if err != nil {
		err = errors.Wrap(err, "Cannot delete subnet cidr reservation")
		_ = HandleEC2Error(err, span)
		return nil, err
	}
	return output, nil
}

func (s *EC2Session) GetRouteTables(ctx context.Context) ([]*ec2.RouteTable, error) {
	ctx, span := trace.StartSpan(ctx, "GetRouteTables")
	defer span.End()

	ec2client := ec2.New(s.Session)
	input := &ec2.DescribeRouteTablesInput{}

	var routeTables []*ec2.RouteTable
	err := ec2client.DescribeRouteTablesPagesWithContext(ctx, input, func(output *ec2.DescribeRouteTablesOutput, hasNextPage bool) bool {
		routeTables = append(routeTables, output.RouteTables...)
		return true
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot get route tables")
		_ = HandleEC2Error(err, span)
		return nil, err
	}

	return routeTables, nil
}
