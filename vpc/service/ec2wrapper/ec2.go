package ec2wrapper

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netflix/titus-executor/logger"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	lru "github.com/hashicorp/golang-lru"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
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
	GetInterfaceByIdx(ctx context.Context, deviceIdx uint32) (EC2NetworkInterfaceSession, error)
}

type EC2NetworkInterfaceSession interface {
	RawSession
	ElasticNetworkInterfaceID() string

	GetSubnet(ctx context.Context, strategy CacheStrategy) (*ec2.Subnet, error)
	GetSubnetByID(ctx context.Context, subnetID string, strategy CacheStrategy) (*ec2.Subnet, error)
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
		sessions:  make(map[key]*ec2BaseSession),
		expvarMap: expvar.NewMap("session"),
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
	sessionsLock sync.RWMutex
	sessions     map[key]*ec2BaseSession
	expvarMap    *expvar.Map
}

func (sessionManager *ec2SessionManager) getSession(ctx context.Context, region, accountID string) *ec2BaseSession {
	// TODO: Validate the account ID is only integers.

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

	newCtx := logger.WithLogger(context.Background(), logger.G(ctx))
	instanceSession.batchENIDescriber = NewBatchENIDescriber(newCtx, time.Second, 50, instanceSession.session)

	sessionManager.sessionsLock.Lock()
	defer sessionManager.sessionsLock.Unlock()
	sessionManager.sessions[sessionKey] = instanceSession
	sessionManager.expvarMap.Set(sessionKey.String(), instanceSession)

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
	session           *session.Session
	instanceCache     *lru.Cache
	subnetCache       *lru.Cache
	interfaceCache    *lru.Cache
	batchENIDescriber *BatchENIDescriber
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
