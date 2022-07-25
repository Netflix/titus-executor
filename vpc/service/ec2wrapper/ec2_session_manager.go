package ec2wrapper

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	ccache "github.com/karlseguin/ccache/v2"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"golang.org/x/sync/singleflight"
)

var (
	invalidateInstanceFromCache = stats.Int64("invalidateInstanceFromCache.count", "Instance invalidated from cache", "")
	storedInstanceInCache       = stats.Int64("storeInstanceInCache.count", "How many times we stored instances in the cache", "")
	getInstanceFromCache        = stats.Int64("getInstanceFromCache.count", "How many times getInstance was tried from cache", "")
	getInstanceFromCacheSuccess = stats.Int64("getInstanceFromCache.success.count", "How many times getInstance from cache succeeded", "")
	getInstanceMs               = stats.Float64("getInstance.latency", "The time to fetch an instance", "ns")
	getInstanceCount            = stats.Int64("getInstance.count", "How many times getInstance was called", "")
	getInstanceSuccess          = stats.Int64("getInstance.success.count", "How many times getInstance succeeded", "")
	cachedInstances             = stats.Int64("cache.instances", "How many instances are cached", "")
	cachedInstancesFreed        = stats.Int64("cache.instance.freed", "How many instances have been evicted from cache", "")
)

var (
	keyRegion    = tag.MustNewKey("region")
	keyAccountID = tag.MustNewKey("accountId")
)

func NewEC2SessionManager(workerRole string) *EC2SessionManager {
	sessionManager := &EC2SessionManager{
		baseSession:  session.Must(session.NewSession()),
		sessions:     &sync.Map{},
		singleflight: &singleflight.Group{},
		workerRole:   workerRole,
		NewSts:       func(p client.ConfigProvider, cfgs ...*aws.Config) stsiface.STSAPI { return sts.New(p, cfgs...) },
		NewEC2:       func(p client.ConfigProvider, cfgs ...*aws.Config) ec2iface.EC2API { return ec2.New(p, cfgs...) },
	}

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
	workerRole  string
	baseSession *session.Session
	// Function used to create a new STS service client
	NewSts func(p client.ConfigProvider, cfgs ...*aws.Config) stsiface.STSAPI
	// Function used to create a new EC2 service client
	NewEC2 func(p client.ConfigProvider, cfgs ...*aws.Config) ec2iface.EC2API

	sessions     *sync.Map
	singleflight *singleflight.Group
}

func (sessionManager *EC2SessionManager) GetSessionFromInstanceIdentity(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (*EC2Session, error) {
	return sessionManager.GetSessionFromAccountAndRegion(ctx, Key{Region: instanceIdentity.Region, AccountID: instanceIdentity.AccountID})
}

func (sessionManager *EC2SessionManager) GetSessionFromAccountAndRegion(ctx context.Context, sessionKey Key) (*EC2Session, error) {
	logger.G(ctx).WithField("AccountID", sessionKey.AccountID).Debug("Getting session")
	ctx, span := trace.StartSpan(ctx, "GetSessionFromAccountAndRegion")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("AccountID", sessionKey.AccountID), trace.StringAttribute("Region", sessionKey.Region))

	// TODO: Validate the account ID is only integers.
	// TODO: Metrics
	v, err, shared := sessionManager.singleflight.Do(sessionKey.String(), func() (interface{}, error) {
		val, ok := sessionManager.sessions.Load(sessionKey.String())
		if ok {
			return val, nil
		}

		ec2Session := &EC2Session{}
		config := aws.NewConfig()

		// TODO: Make behind flag
		//  .WithLogLevel(aws.LogDebugWithHTTPBody)
		if sessionKey.Region != "" {
			config.Region = &sessionKey.Region
		}

		var err error
		ec2Session.Session, err = session.NewSession(config)
		if err != nil {
			return nil, err
		}

		// Gotta do the assumerole flow
		newArn := arn.ARN{
			Partition: "aws",
			Service:   "iam",
			AccountID: sessionKey.AccountID,
			Resource:  "role/" + sessionManager.workerRole,
		}

		credentials := stscreds.NewCredentials(ec2Session.Session, newArn.String())
		// Copy the original config
		config2 := *config
		config2.Credentials = credentials
		if sessionKey.Region != "" {
			config2.Region = &sessionKey.Region
		}
		logger.G(ctx).WithField("arn", newArn).Info("Setting up assume role")
		ec2Session.Session, err = session.NewSession(&config2)
		if err != nil {
			return nil, err
		}
		output, err := sessionManager.NewSts(ec2Session.Session).GetCallerIdentityWithContext(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return nil, err
		}
		logger.G(ctx).WithField("arn", aws.StringValue(output.Arn)).Info("New ARN")

		ec2Session.instanceCache = ccache.New(ccache.Configure().MaxSize(10000).ItemsToPrune(10))
		ec2Session.instanceCache.OnDelete(func(*ccache.Item) {
			stats.Record(ctx, cachedInstancesFreed.M(1))
		})

		go func() {
			mutators := []tag.Mutator{tag.Upsert(keyRegion, sessionKey.Region), tag.Upsert(keyAccountID, sessionKey.AccountID)}
			for {
				time.Sleep(time.Second)
				_ = stats.RecordWithTags(ctx, mutators, cachedInstances.M(int64(ec2Session.instanceCache.ItemCount())))
			}
		}()
		newCtx := logger.WithLogger(context.Background(), logger.G(ctx))
		newEC2 := sessionManager.NewEC2
		ec2Session.batchENIDescriber = NewBatchENIDescriber(newCtx, time.Second, 50, ec2Session.Session, newEC2)
		ec2Session.batchInstancesDescriber = NewBatchInstanceDescriber(newCtx, time.Second, 50, ec2Session.Session, newEC2)
		ec2Session.newEC2 = newEC2

		sessionManager.sessions.Store(sessionKey.String(), ec2Session)
		return ec2Session, nil
	})

	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	span.AddAttributes(trace.BoolAttribute("shared", shared))

	return v.(*EC2Session), nil
}
