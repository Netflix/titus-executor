package ec2wrapper

import (
	"context"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func init() {
	err := view.Register(
		&view.View{
			Name:        getInstanceMs.Name(),
			Description: getInstanceMs.Description(),
			TagKeys:     []tag.Key{keyInstance},
			Measure:     getInstanceMs,
			Aggregation: view.Distribution(),
		},
		&view.View{
			Name:        getInstanceCount.Name(),
			Description: getInstanceCount.Description(),
			TagKeys:     []tag.Key{keyInstance},
			Measure:     getInstanceCount,
			Aggregation: view.Count(),
		},
		&view.View{
			Name:        getInstanceSuccess.Name(),
			Description: getInstanceCount.Description(),
			TagKeys:     []tag.Key{keyInstance},
			Measure:     getInstanceCount,
			Aggregation: view.Count(),
		},
	)
	if err != nil {
		panic(err)
	}
}

var (
	getInstanceMs      = stats.Float64("getInstance.latency", "The time to fetch an instance", "ns")
	getInstanceCount   = stats.Int64("getInstance.count", "How many times getInstance was called", "")
	getInstanceSuccess = stats.Int64("getInstance.count.success", "How many times getInstance succeeded", "")
)

var (
	keyInstance = tag.MustNewKey("instanceId")
)

type RawSession interface {
	Session(ctx context.Context) (*session.Session, error)
}

type EC2SessionManager interface {
	GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (EC2InstanceSession, error)
	GetSessionFromNetworkInterface(ctx context.Context, ec2instanceSession EC2InstanceSession, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error)
}

type EC2InstanceSession interface {
	RawSession
	GetInstance(ctx context.Context) (*ec2.Instance, error)
	GetSessionFromNetworkInterface(ctx context.Context, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error)
	Region(ctx context.Context) (string, error)
}

type EC2NetworkInterfaceSession interface {
	RawSession
	GetSubnet(ctx context.Context) (*ec2.Subnet, error)
	GetSubnetByID(ctx context.Context, subnetID string) (*ec2.Subnet, error)
	GetDefaultSecurityGroups(ctx context.Context) ([]*string, error)
	ModifySecurityGroups(ctx context.Context, groupIds []*string) error
	GetNetworkInterface(ctx context.Context) (*ec2.NetworkInterface, error)
	AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error)
	AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error)
	UnassignPrivateIPAddresses(ctx context.Context, unassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error)
}

func NewEC2SessionManager() EC2SessionManager {
	return &ec2SessionManager{
		sessions: make(map[key]*session.Session),
	}
}

type key struct {
	accountID string
	region    string
}

type ec2SessionManager struct {
	sessionsLock sync.RWMutex
	sessions     map[key]*session.Session
}

func (sessionManager *ec2SessionManager) getSession(ctx context.Context, region, accountID string) *session.Session {
	// TODO: Metrics

	// TODO: Do get called identity, and check if assumerole is required for account assumption
	sessionKey := key{
		region:    region,
		accountID: accountID,
	}
	sessionManager.sessionsLock.RLock()
	instanceSession, ok := sessionManager.sessions[sessionKey]
	sessionManager.sessionsLock.RUnlock()
	if ok {
		return instanceSession
	}

	config := &aws.Config{}
	if region != "" {
		config.Region = &region
	}

	// TODO: Return an error here
	instanceSession = session.Must(session.NewSession(config))

	sessionManager.sessionsLock.Lock()
	defer sessionManager.sessionsLock.Unlock()
	sessionManager.sessions[sessionKey] = instanceSession

	return instanceSession
}

func (sessionManager *ec2SessionManager) GetSessionFromNetworkInterface(ctx context.Context, ec2instanceSession EC2InstanceSession, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error) {
	region, err := ec2instanceSession.Region(ctx)
	if err != nil {
		return nil, err
	}
	session := sessionManager.getSession(ctx, region, aws.StringValue(instanceNetworkInterface.OwnerId))

	return &ec2NetworkInterfaceSession{
		ec2BaseSession:           &ec2BaseSession{session: session},
		instanceNetworkInterface: instanceNetworkInterface,
	}, nil
}

func (sessionManager *ec2SessionManager) GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (EC2InstanceSession, error) {
	session := sessionManager.getSession(ctx, instanceIdentity.Region, instanceIdentity.AccountID)
	return &ec2InstanceSession{ec2BaseSession: &ec2BaseSession{session: session}, instanceIdentity: instanceIdentity}, nil
}

type ec2BaseSession struct {
	session *session.Session
}

func (s *ec2BaseSession) Session(ctx context.Context) (*session.Session, error) {
	return s.session, nil
}

type ec2InstanceSession struct {
	*ec2BaseSession
	instanceIdentity *vpcapi.InstanceIdentity
}

func (s *ec2InstanceSession) GetSessionFromNetworkInterface(ctx context.Context, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error) {
	return &ec2NetworkInterfaceSession{
		ec2BaseSession:           s.ec2BaseSession,
		instanceNetworkInterface: instanceNetworkInterface,
	}, nil
}

func (s *ec2InstanceSession) Region(ctx context.Context) (string, error) {
	if s.instanceIdentity.Region != "" {
		return s.instanceIdentity.Region, nil
	}
	// TODO: Try to retrieve the region from the instance identity document.

	return "", errors.New("Cannot find instance region")
}

func (s *ec2InstanceSession) GetInstance(ctx context.Context) (*ec2.Instance, error) {
	ctx, span := trace.StartSpan(ctx, "getInstance")
	defer span.End()
	start := time.Now()
	ctx, err := tag.New(ctx, tag.Upsert(keyInstance, s.instanceIdentity.GetInstanceID()))
	if err != nil {
		return nil, err
	}
	stats.Record(ctx, getInstanceCount.M(1))

	ec2client := ec2.New(s.session)
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{s.instanceIdentity.GetInstanceID()}),
	})

	if err != nil {
		logger.G(ctx).WithField("ec2InstanceId", s.instanceIdentity.GetInstanceID()).Error("Could not get EC2 Instance")
		switch awsErr := err.(type) {
		case awserr.Error:
			if awsErr.Code() == "InvalidInstanceID.NotFound" {
				span.SetStatus(trace.Status{
					Code:    trace.StatusCodeNotFound,
					Message: awsErr.Message(),
				})
				return nil, status.Error(codes.NotFound, awsErr.Error())
			}
		default:
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeUnknown,
				Message: err.Error(),
			})
			return nil, err
		}
	}

	if describeInstancesOutput.Reservations == nil || len(describeInstancesOutput.Reservations) == 0 {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: "Describe Instances returned 0 reservations",
		})
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 reservations")
	}
	if describeInstancesOutput.Reservations[0].Instances == nil || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeNotFound,
			Message: "Describe Instances returned 0 instances",
		})
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 instances")
	}

	stats.Record(ctx, getInstanceMs.M(float64(time.Since(start).Nanoseconds())), getInstanceSuccess.M(1))
	return describeInstancesOutput.Reservations[0].Instances[0], nil
}

type ec2NetworkInterfaceSession struct {
	*ec2BaseSession
	instanceNetworkInterface *ec2.InstanceNetworkInterface
}

func (s *ec2NetworkInterfaceSession) GetNetworkInterface(ctx context.Context) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "getNetworkInterface")
	defer span.End()
	ec2client := ec2.New(s.session)

	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{s.instanceNetworkInterface.NetworkInterfaceId},
	}

	describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
	// TODO: Work around rate limiting here, and do some basic retries
	if err != nil {
		return nil, status.Convert(errors.Wrap(err, "Cannot describe network interfaces")).Err()
	}

	return describeNetworkInterfacesOutput.NetworkInterfaces[0], nil
}

func (s *ec2NetworkInterfaceSession) ModifySecurityGroups(ctx context.Context, groupIds []*string) error {
	ctx, span := trace.StartSpan(ctx, "modifySecurityGroups")
	defer span.End()
	ec2client := ec2.New(s.session)
	networkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             groupIds,
		NetworkInterfaceId: s.instanceNetworkInterface.NetworkInterfaceId,
	}
	_, err := ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, networkInterfaceAttributeInput)

	if err != nil {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeUnknown,
			Message: err.Error(),
		})
		return status.Convert(errors.Wrap(err, "Cannot modify security groups")).Err()
	}

	return nil
}

func (s *ec2NetworkInterfaceSession) GetSubnet(ctx context.Context) (*ec2.Subnet, error) {
	return s.GetSubnetByID(ctx, aws.StringValue(s.instanceNetworkInterface.SubnetId))
}

func (s *ec2NetworkInterfaceSession) GetSubnetByID(ctx context.Context, subnetID string) (*ec2.Subnet, error) {
	ctx, span := trace.StartSpan(ctx, "getSubnet")
	defer span.End()

	// TODO: Cache
	ec2client := ec2.New(s.session)
	describeSubnetsOutput, err := ec2client.DescribeSubnetsWithContext(ctx, &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{&subnetID},
	})
	if err != nil {
		logger.G(ctx).WithField("subnetID", subnetID).Error("Could not get Subnet")
		switch awsErr := err.(type) {
		case awserr.Error:
			if awsErr.Code() == "InvalidSubnetID.NotFound" {
				span.SetStatus(trace.Status{
					Code:    trace.StatusCodeNotFound,
					Message: awsErr.Message(),
				})
				return nil, status.Error(codes.NotFound, awsErr.Error())
			}
		default:
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeUnknown,
				Message: err.Error(),
			})
			return nil, err
		}
	}

	subnet := describeSubnetsOutput.Subnets[0]
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
		return nil, errors.Wrap(err, "Unable to unassign private IP addresses")
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

func GetInterfaceByIdx(instance *ec2.Instance, deviceIdx uint32) *ec2.InstanceNetworkInterface {
	for _, ni := range instance.NetworkInterfaces {
		if aws.Int64Value(ni.Attachment.DeviceIndex) == int64(deviceIdx) {
			return ni
		}
	}

	return nil
}
