package ec2wrapper

import (
	"context"
	"expvar"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/arn"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/session"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/sts"
	"github.com/Netflix/titus-executor/logger"
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

var sessionManagerID int64

func NewEC2SessionManager() *EC2SessionManager {
	id := atomic.AddInt64(&sessionManagerID, 1)
	sessionManager := &EC2SessionManager{
		baseSession: session.Must(session.NewSession()),
		sessions:    make(map[Key]*EC2Session),
		expvarMap:   expvar.NewMap("session"),
	}
	sessionManagerMap.Set(fmt.Sprintf("sessionManager-%d", id), sessionManager.expvarMap)

	return sessionManager
}

type Key struct {
	AccountID string
	Region    string
}

func (k Key) String() string {
	return fmt.Sprintf("%s-%s", k.AccountID, k.Region)
}

type EC2SessionManager struct {
	baseSession        *session.Session
	callerIdentityLock sync.RWMutex
	callerIdentity     *sts.GetCallerIdentityOutput

	sessionsLock sync.RWMutex
	sessions     map[Key]*EC2Session
	expvarMap    *expvar.Map
}

func (sessionManager *EC2SessionManager) getCallerIdentity(ctx context.Context) (*sts.GetCallerIdentityOutput, error) {
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
func (sessionManager *EC2SessionManager) GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (*EC2Session, error) {
	return sessionManager.GetSessionFromAccountAndRegion(ctx, Key{Region: instanceIdentity.Region, AccountID: instanceIdentity.AccountID})
}

func (sessionManager *EC2SessionManager) GetSessionFromAccountAndRegion(ctx context.Context, sessionKey Key) (*EC2Session, error) {
	// TODO: Validate the account ID is only integers.
	logger.G(ctx).WithField("AccountID", sessionKey.AccountID).Debug("Getting session")
	// TODO: Metrics
	sessionManager.sessionsLock.RLock()
	instanceSession, ok := sessionManager.sessions[sessionKey]
	sessionManager.sessionsLock.RUnlock()
	if ok {
		return instanceSession, nil
	}

	ctx, span := trace.StartSpan(ctx, "describer")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("AccountID", sessionKey.AccountID), trace.StringAttribute("Region", sessionKey.Region))

	myIdentity, err := sessionManager.getCallerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	// This can race, but that's okay
	instanceSession = &EC2Session{}
	config := aws.NewConfig()

	// TODO: Make behind flag
	//  .WithLogLevel(aws.LogDebugWithHTTPBody)
	if sessionKey.Region != "" {
		config.Region = &sessionKey.Region
	}

	instanceSession.Session, err = session.NewSession(config)
	if err != nil {
		return nil, err
	}
	if aws.StringValue(myIdentity.Account) != sessionKey.AccountID {
		// Gotta do the assumerole flow
		currentARN, err := arn.Parse(aws.StringValue(myIdentity.Arn))
		if err != nil {
			return nil, err
		}
		newArn := arn.ARN{
			Partition: "aws",
			Service:   "iam",
			AccountID: sessionKey.AccountID,
			Resource:  "role/" + strings.Split(currentARN.Resource, "/")[1],
		}

		credentials := stscreds.NewCredentials(instanceSession.Session, newArn.String())
		// Copy the original config
		config2 := *config
		config2.Credentials = credentials
		if sessionKey.Region != "" {
			config2.Region = &sessionKey.Region
		}
		logger.G(ctx).WithField("arn", newArn).WithField("currentARN", currentARN).Info("Setting up assume role")
		instanceSession.Session, err = session.NewSession(&config2)
		if err != nil {
			return nil, err
		}
		output, err := sts.New(instanceSession.Session).GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
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

	newCtx := logger.WithLogger(context.Background(), logger.G(ctx))
	instanceSession.batchENIDescriber = NewBatchENIDescriber(newCtx, time.Second, 50, instanceSession.Session)

	sessionManager.sessionsLock.Lock()
	defer sessionManager.sessionsLock.Unlock()
	sessionManager.sessions[sessionKey] = instanceSession
	sessionManager.expvarMap.Set(sessionKey.String(), instanceSession)

	return instanceSession, nil
}
