package ec2wrapper

import (
	"context"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CacheStrategy int

const (
	NoCache                       = 0
	InvalidateCache CacheStrategy = 1 << iota
	StoreInCache    CacheStrategy = 1 << iota
	FetchFromCache  CacheStrategy = 1 << iota
)

const (
	UseCache CacheStrategy = StoreInCache | FetchFromCache
)

var (
	invalidateInstanceFromCache = stats.Int64("invalidateInstanceFromCache.count", "Instance invalidated from cache", "")
	storedInstanceInCache       = stats.Int64("storeInstanceInCache.count", "How many times we stored instances in the cache", "")
	getInstanceFromCache        = stats.Int64("getInstanceFromCache.count", "How many times getInstance was tried from cache", "")
	getInstanceFromCacheSuccess = stats.Int64("getInstanceFromCache.success.count", "How many times getInstance from cache succeeded", "")
	getInstanceMs               = stats.Float64("getInstance.latency", "The time to fetch an instance", "ns")
	getInstanceCount            = stats.Int64("getInstance.count", "How many times getInstance was called", "")
	getInstanceSuccess          = stats.Int64("getInstance.success.count", "How many times getInstance succeeded", "")
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
	// GetInstance returns the EC2 instance. It may be cached, unless forceRefresh is true
	GetInstance(ctx context.Context, strategy CacheStrategy) (*ec2.Instance, error)
	GetSessionFromNetworkInterface(ctx context.Context, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error)
	Region(ctx context.Context) (string, error)
}

type EC2NetworkInterfaceSession interface {
	RawSession
	GetSubnet(ctx context.Context, strategy CacheStrategy) (*ec2.Subnet, error)
	GetSubnetByID(ctx context.Context, subnetID string, strategy CacheStrategy) (*ec2.Subnet, error)
	GetDefaultSecurityGroups(ctx context.Context) ([]*string, error)
	ModifySecurityGroups(ctx context.Context, groupIds []*string) error
	GetNetworkInterface(ctx context.Context, strategy CacheStrategy) (*ec2.NetworkInterface, error)
	AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error)
	AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error)
	UnassignPrivateIPAddresses(ctx context.Context, unassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error)
}

func NewEC2SessionManager() EC2SessionManager {
	return &ec2SessionManager{
		sessions: make(map[key]*ec2BaseSession),
	}
}

type key struct {
	accountID string
	region    string
}

type ec2SessionManager struct {
	sessionsLock sync.RWMutex
	sessions     map[key]*ec2BaseSession
}

func (sessionManager *ec2SessionManager) getSession(ctx context.Context, region, accountID string) *ec2BaseSession {
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

	// This can race, but that's okay
	instanceSession = &ec2BaseSession{}
	config := &aws.Config{}
	if region != "" {
		config.Region = &region
	}

	// TODO: Return an error here
	instanceSession.session = session.Must(session.NewSession(config))
	c, err := lru.New(10000)
	if err != nil {
		panic(err)
	}
	instanceSession.instanceCache = c

	c, err = lru.New(100)
	if err != nil {
		panic(err)
	}
	instanceSession.subnetCache = c

	c, err = lru.New(10000)
	if err != nil {
		panic(err)
	}
	instanceSession.interfaceCache = c

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
		ec2BaseSession:           session,
		instanceNetworkInterface: instanceNetworkInterface,
	}, nil
}

func (sessionManager *ec2SessionManager) GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (EC2InstanceSession, error) {
	session := sessionManager.getSession(ctx, instanceIdentity.Region, instanceIdentity.AccountID)
	return &ec2InstanceSession{ec2BaseSession: session, instanceIdentity: instanceIdentity}, nil
}

type ec2BaseSession struct {
	session        *session.Session
	instanceCache  *lru.Cache
	subnetCache    *lru.Cache
	interfaceCache *lru.Cache
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

func (s *ec2InstanceSession) GetInstance(ctx context.Context, strategy CacheStrategy) (*ec2.Instance, error) {
	ctx, span := trace.StartSpan(ctx, "getInstance")
	defer span.End()
	start := time.Now()
	ctx, err := tag.New(ctx, tag.Upsert(keyInstance, s.instanceIdentity.GetInstanceID()))
	if err != nil {
		return nil, err
	}
	stats.Record(ctx, getInstanceCount.M(1))

	if strategy&InvalidateCache > 0 {
		stats.Record(ctx, invalidateInstanceFromCache.M(1))
		s.instanceCache.Remove(s.instanceIdentity.InstanceID)
	}
	if strategy&FetchFromCache > 0 {
		stats.Record(ctx, getInstanceFromCache.M(1))
		instance, ok := s.instanceCache.Get(s.instanceIdentity.InstanceID)
		if ok {
			stats.Record(ctx, getInstanceFromCacheSuccess.M(1), getInstanceSuccess.M(1))
			return instance.(*ec2.Instance), nil
		}
	}

	ec2client := ec2.New(s.session)
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{s.instanceIdentity.GetInstanceID()}),
	})

	if err != nil {
		logger.G(ctx).WithError(err).WithField("ec2InstanceId", s.instanceIdentity.GetInstanceID()).Error("Could not get EC2 Instance")
		return nil, handleEC2Error(err, span)
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
	if strategy&StoreInCache > 0 {
		stats.Record(ctx, storedInstanceInCache.M(1))
		s.instanceCache.Add(s.instanceIdentity.InstanceID, describeInstancesOutput.Reservations[0].Instances[0])
	}
	return describeInstancesOutput.Reservations[0].Instances[0], nil
}
