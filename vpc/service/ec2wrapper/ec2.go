package ec2wrapper

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	lru "github.com/hashicorp/golang-lru"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
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

var sessionManagerMap *expvar.Map

func init() {
	sessionManagerMap = expvar.NewMap("sessionManagers")
}

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
	GetSubnetByID(ctx context.Context, subnetID string, strategy CacheStrategy) (*ec2.Subnet, error)
}

type EC2SessionManager interface {
	GetSessionFromAccountAndRegion(ctx context.Context, accountID, region string) (EC2Session, error)
	GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (EC2InstanceSession, error)
	GetSessionFromInstanceNetworkInterface(ctx context.Context, ec2instanceSession EC2InstanceSession, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error)
	GetSessionFromNetworkInterface(ctx context.Context, ec2Session EC2Session, networkInterface *ec2.NetworkInterface) (EC2NetworkInterfaceSession, error)
}

type EC2InstanceSession interface {
	RawSession
	// GetInstance returns the EC2 instance. It may be cached, unless forceRefresh is true
	GetInstance(ctx context.Context, strategy CacheStrategy) (*ec2.Instance, error)
	GetSessionFromNetworkInterface(ctx context.Context, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error)
	GetInterfaceByIdx(ctx context.Context, deviceIdx uint32) (EC2NetworkInterfaceSession, error)
	Region(ctx context.Context) (string, error)
}

type EC2Session interface {
	RawSession
}

type EC2NetworkInterfaceSession interface {
	RawSession
	ElasticNetworkInterfaceID() string

	GetSubnet(ctx context.Context, strategy CacheStrategy) (*ec2.Subnet, error)
	GetDefaultSecurityGroups(ctx context.Context) ([]*string, error)
	ModifySecurityGroups(ctx context.Context, groupIds []*string) error
	GetNetworkInterface(ctx context.Context, deadline time.Duration) (*ec2.NetworkInterface, error)
	AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error)
	AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error)
	UnassignPrivateIPAddresses(ctx context.Context, unassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error)
}

var sessionManagerID int64

func NewEC2SessionManager() EC2SessionManager {
	id := atomic.AddInt64(&sessionManagerID, 1)
	sessionManager := &ec2SessionManager{
		baseSession: session.Must(session.NewSession()),
		sessions:    make(map[key]*ec2BaseSession),
		expvarMap:   expvar.NewMap("session"),
	}
	sessionManagerMap.Set(fmt.Sprintf("sessionManager-%d", id), sessionManager.expvarMap)

	return sessionManager
}

type key struct {
	accountID string
	region    string
}

func (k key) String() string {
	return fmt.Sprintf("%s-%s", k.accountID, k.region)
}

type ec2SessionManager struct {
	baseSession        *session.Session
	callerIdentityLock sync.RWMutex
	callerIdentity     *sts.GetCallerIdentityOutput

	sessionsLock sync.RWMutex
	sessions     map[key]*ec2BaseSession
	expvarMap    *expvar.Map
}

func (sessionManager *ec2SessionManager) getCallerIdentity(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
	ctx, span := trace.StartSpan(ctx, "getCallerIdentity")
	defer span.End()
	sessionManager.callerIdentityLock.RLock()
	ret := sessionManager.callerIdentity
	sessionManager.callerIdentityLock.RUnlock()
	if ret != nil {
		return ret, nil
	}

	sessionManager.callerIdentityLock.Lock()
	defer sessionManager.callerIdentityLock.Unlock()
	// To prevent the thundering herd
	if sessionManager.callerIdentity != nil {
		return sessionManager.callerIdentity, nil
	}
	stsClient := sts.New(sessionManager.baseSession)
	output, err := stsClient.GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, HandleEC2Error(err, span)
	}
	sessionManager.callerIdentity = output

	return output, nil
}

func (sessionManager *ec2SessionManager) getSession(ctx context.Context, region, accountID string) (*ec2BaseSession, error) {
	// TODO: Validate the account ID is only integers.
	logger.G(ctx).WithField("accountID", accountID).Debug("Getting session")
	// TODO: Metrics
	sessionKey := key{
		region:    region,
		accountID: accountID,
	}
	sessionManager.sessionsLock.RLock()
	instanceSession, ok := sessionManager.sessions[sessionKey]
	sessionManager.sessionsLock.RUnlock()
	if ok {
		return instanceSession, nil
	}

	ctx, span := trace.StartSpan(ctx, "describer")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("accountID", accountID), trace.StringAttribute("region", region))

	myIdentity, err := sessionManager.getCallerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	// This can race, but that's okay
	instanceSession = &ec2BaseSession{}
	config := aws.NewConfig()

	// TODO: Make behind flag
	//  .WithLogLevel(aws.LogDebugWithHTTPBody)
	if region != "" {
		config.Region = &region
	}

	instanceSession.session, err = session.NewSession(config)
	if err != nil {
		return nil, err
	}
	if aws.StringValue(myIdentity.Account) != accountID {
		// Gotta do the assumerole flow
		currentARN, err := arn.Parse(aws.StringValue(myIdentity.Arn))
		if err != nil {
			return nil, err
		}
		newArn := arn.ARN{
			Partition: "aws",
			Service:   "iam",
			AccountID: accountID,
			Resource:  "role/" + strings.Split(currentARN.Resource, "/")[1],
		}

		credentials := stscreds.NewCredentials(instanceSession.session, newArn.String())
		// Copy the original config
		config2 := *config
		config2.Credentials = credentials
		if region != "" {
			config2.Region = &region
		}
		logger.G(ctx).WithField("arn", newArn).WithField("currentARN", currentARN).Info("Setting up assume role")
		instanceSession.session, err = session.NewSession(&config2)
		if err != nil {
			return nil, err
		}
		output, err := sts.New(instanceSession.session).GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return nil, err
		}
		logger.G(ctx).WithField("arn", aws.StringValue(output.Arn)).Info("New ARN")
	} else {
		logger.G(ctx).Info("Setting up session")
	}

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

	newCtx := logger.WithLogger(context.Background(), logger.G(ctx))
	instanceSession.batchENIDescriber = NewBatchENIDescriber(newCtx, time.Second, 50, instanceSession.session)

	sessionManager.sessionsLock.Lock()
	defer sessionManager.sessionsLock.Unlock()
	sessionManager.sessions[sessionKey] = instanceSession
	sessionManager.expvarMap.Set(sessionKey.String(), instanceSession)

	return instanceSession, nil
}

func (sessionManager *ec2SessionManager) GetSessionFromInstanceNetworkInterface(ctx context.Context, ec2instanceSession EC2InstanceSession, instanceNetworkInterface *ec2.InstanceNetworkInterface) (EC2NetworkInterfaceSession, error) {
	region, err := ec2instanceSession.Region(ctx)
	if err != nil {
		return nil, err
	}
	session, err := sessionManager.getSession(ctx, region, aws.StringValue(instanceNetworkInterface.OwnerId))
	if err != nil {
		return nil, err
	}

	return &ec2NetworkInterfaceSession{
		ec2BaseSession:   session,
		networkInterface: &instanceNetworkInterfaceWrapper{instanceNetworkInterface: instanceNetworkInterface},
	}, nil
}

func (sessionManager *ec2SessionManager) GetSessionFromNetworkInterface(ctx context.Context, ec2Session EC2Session, networkInterface *ec2.NetworkInterface) (EC2NetworkInterfaceSession, error) {
	az := aws.StringValue(networkInterface.AvailabilityZone)
	region := az[0 : len(az)-1]
	session, err := sessionManager.getSession(ctx, region, aws.StringValue(networkInterface.OwnerId))
	if err != nil {
		return nil, err
	}

	return &ec2NetworkInterfaceSession{
		ec2BaseSession:   session,
		networkInterface: &networkInterfaceWrapper{networkInterface: networkInterface},
	}, nil
}

func (sessionManager *ec2SessionManager) GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (EC2InstanceSession, error) {
	logger.G(ctx).WithField("instanceIdentity", instanceIdentity).Debug("Trying to get session")
	session, err := sessionManager.getSession(ctx, instanceIdentity.Region, instanceIdentity.AccountID)
	if err != nil {
		return nil, err
	}

	return &ec2InstanceSession{ec2BaseSession: session, instanceIdentity: instanceIdentity}, nil
}

func (sessionManager *ec2SessionManager) GetSessionFromAccountAndRegion(ctx context.Context, accountID, region string) (EC2Session, error) {
	session, err := sessionManager.getSession(ctx, region, accountID)
	if err != nil {
		return nil, err
	}
	return &ec2Session{ec2BaseSession: session}, nil
}

type ec2BaseSession struct {
	session           *session.Session
	instanceCache     *lru.Cache
	subnetCache       *lru.Cache
	interfaceCache    *lru.Cache
	batchENIDescriber *BatchENIDescriber
}

func (s *ec2BaseSession) Region(ctx context.Context) (string, error) {
	if s.session.Config.Region == nil {
		return "us-east-1", nil
	}
	return *s.session.Config.Region, nil
}

// This is for expvar, it's meant to return JSON
func (s *ec2BaseSession) String() string {
	state := struct {
		InstanceCacheSize  int `json:"instanceCacheSize"`
		SubnetCacheSize    int `json:"subnetCacheSize"`
		InterfaceCacheSize int `json:"interfaceCacheSize"`

		InstanceCacheKeys  []interface{} `json:"instanceCacheKeys"`
		SubnetCacheKeys    []interface{} `json:"subnetCacheKeys"`
		InterfaceCacheKeys []interface{} `json:"interfaceCacheKeys"`
	}{
		InstanceCacheSize:  s.instanceCache.Len(),
		SubnetCacheSize:    s.subnetCache.Len(),
		InterfaceCacheSize: s.interfaceCache.Len(),
		InstanceCacheKeys:  s.instanceCache.Keys(),
		SubnetCacheKeys:    s.subnetCache.Keys(),
		InterfaceCacheKeys: s.interfaceCache.Keys(),
	}
	marshaled, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		// This shouldn't happen
		errorMessage := struct {
			ErrorMessage string
		}{
			ErrorMessage: err.Error(),
		}
		data, err2 := json.Marshal(errorMessage)
		if err2 != nil {
			panic(err2)
		}
		return string(data)
	}
	return string(marshaled)

}

func (s *ec2BaseSession) Session(ctx context.Context) (*session.Session, error) {
	return s.session, nil
}

func (s *ec2BaseSession) GetSubnetByID(ctx context.Context, subnetID string, strategy CacheStrategy) (*ec2.Subnet, error) {
	ctx, span := trace.StartSpan(ctx, "getSubnetbyID")
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
		return nil, HandleEC2Error(err, span)
	}

	subnet := describeSubnetsOutput.Subnets[0]
	if strategy&StoreInCache > 0 {
		s.subnetCache.Add(subnetID, subnet)
	}
	return subnet, nil
}
