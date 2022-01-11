package service

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/services"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"go.opencensus.io/trace"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	ccache "github.com/karlseguin/ccache/v2"
	"github.com/pkg/errors"
	"github.com/soheilhy/cmux"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

var (
	grpcRequest   = stats.Int64("grpcRequest", "Statistics about gRPC requests", "")
	grpcRequestNs = stats.Int64("grpcRequestNs", "Time of gRPC Request", "ns")
)

func init() {
	if err := view.Register(
		&view.View{
			Name:        grpcRequest.Name(),
			Description: grpcRequest.Description(),
			Measure:     grpcRequest,
			Aggregation: view.Count(),
			TagKeys:     []tag.Key{services.MethodTag, services.ReturnCodeTag},
		},
		&view.View{
			Name:        grpcRequestNs.Name(),
			Description: grpcRequestNs.Description(),
			Measure:     grpcRequestNs,
			Aggregation: view.Distribution(),
			TagKeys:     []tag.Key{services.MethodTag, services.ReturnCodeTag},
		}); err != nil {
		panic(err)
	}
}

type vpcService struct {
	// We hope this is globally unique
	hostname string
	ec2      *ec2wrapper.EC2SessionManager

	db    *sql.DB
	dbURL string

	authoritativePublicKey ed25519.PublicKey
	hostPublicKeySignature []byte
	hostPrivateKey         ed25519.PrivateKey
	hostPublicKey          ed25519.PublicKey

	gcTimeout       time.Duration
	refreshInterval time.Duration

	refreshLock *semaphore.Weighted

	dbRateLimiter *rate.Limiter

	trunkNetworkInterfaceDescription  string
	branchNetworkInterfaceDescription string
	subnetCIDRReservationDescription  string

	trunkTracker              *trunkTrackerCache
	invalidSecurityGroupCache *ccache.Cache

	subnetCacheExpirationTime time.Duration
	concurrentRequests        *semaphore.Weighted

	routesCache sync.Map

	workerID int64
	counters sync.Map

	// PB Services:
	vpcapi.TitusAgentVPCServiceServer
	titus.UserIPServiceServer
	titus.ValidatorIPServiceServer
	titus.TitusAgentVPCInformationServiceServer
	titus.TitusAgentSecurityGroupServiceServer
}

// trunkTrackerCache keeps track of trunk ENIs, and at least locally (on-instance) tries to reduce contention for operations
// on that trunk ENI.
type trunkTrackerCache struct {
	cache                     *ccache.Cache
	generatorTrackerAdderLock singleflight.Group
}

func newTrunkTrackerCache() *trunkTrackerCache {
	return &trunkTrackerCache{
		cache: ccache.New(ccache.Configure().MaxSize(20000).Track()),
	}
}

// lockTrunk locks the trunk ENI referenced to be string. It is expected that the
func (t *trunkTrackerCache) acquire(ctx context.Context, trunkENI string) (func(), error) {
	ctx, span := trace.StartSpan(ctx, "trunkTrackerCache.acquire")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("eni", trunkENI),
		trace.StringAttribute("trunk", trunkENI),
	)
	val, err, _ := t.generatorTrackerAdderLock.Do(trunkENI, func() (interface{}, error) {
		item := t.cache.TrackingGet(trunkENI)
		if item != ccache.NilTracked {
			return item, nil
		}

		lock := semaphore.NewWeighted(1)
		return t.cache.TrackingSet(trunkENI, lock, 24*time.Hour), nil
	})

	if err != nil {
		err = fmt.Errorf("Could not fetch trunk tracker item from cache: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	trackedItem := val.(ccache.TrackedItem)
	sem := trackedItem.Value().(*semaphore.Weighted)
	err = sem.Acquire(ctx, 1)
	if err != nil {
		err = fmt.Errorf("Could not acquire tracking semaphore %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return func() {
		trackedItem.Release()
		sem.Release(1)
	}, nil
}

type Config struct {
	Listener              net.Listener
	DB                    *sql.DB
	DBURL                 string
	Key                   vpcapi.PrivateKey
	MaxConcurrentRefresh  int64
	MaxConcurrentRequests int
	GCTimeout             time.Duration
	ReconcileInterval     time.Duration
	RefreshInterval       time.Duration
	TLSConfig             *tls.Config

	EnabledLongLivedTasks []string
	EnabledTaskLoops      []string

	TrunkNetworkInterfaceDescription  string
	BranchNetworkInterfaceDescription string
	SubnetCIDRReservationDescription  string

	WorkerRole string

	// This is only used for testing.
	disableRouteCache bool
}

func Run(ctx context.Context, config *Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)

	if config.RefreshInterval == 0 {
		panic("Refresh interval is 0")
	}
	logrusEntry := logger.G(ctx).WithField("origin", "grpc")
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)

	if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return errors.Wrap(err, "Cannot get hostname")
	}

	if config.TrunkNetworkInterfaceDescription == "" {
		return errors.New("Trunk interface description must be non-empty")
	}

	if config.BranchNetworkInterfaceDescription == "" {
		return errors.New("Branch interface description must be non-empty")
	}

	if config.WorkerRole == "" {
		return errors.New("The worker role must be non-empty")
	}

	vpc := &vpcService{
		hostname: hostname,
		ec2:      ec2wrapper.NewEC2SessionManager(config.WorkerRole),
		db:       config.DB,
		dbURL:    config.DBURL,

		gcTimeout:       config.GCTimeout,
		refreshInterval: config.RefreshInterval,

		refreshLock: semaphore.NewWeighted(config.MaxConcurrentRefresh),

		dbRateLimiter: rate.NewLimiter(1000, 1),

		trunkNetworkInterfaceDescription:  config.TrunkNetworkInterfaceDescription,
		branchNetworkInterfaceDescription: config.BranchNetworkInterfaceDescription,
		subnetCIDRReservationDescription:  config.SubnetCIDRReservationDescription,

		trunkTracker:              newTrunkTrackerCache(),
		invalidSecurityGroupCache: ccache.New(ccache.Configure()),

		// Failures to find subnet (negative result) is never cached. Only positive results are cached.
		// The reconcile interval drives how often the subnets change in the DB. Although they may be out of phase
		// they will never be more than in an completely offset phase if we set the expiration time
		// to the reconcile time.
		subnetCacheExpirationTime: config.ReconcileInterval / 2.0,

		concurrentRequests: semaphore.NewWeighted(int64(config.MaxConcurrentRequests)),
	}

	// TODO: actually validate this
	ed25519key := ed25519.NewKeyFromSeed(config.Key.GetEd25519Key().Rfc8032Key)
	if config.DB != nil {
		longLivedPublicKey := ed25519key.Public().(ed25519.PublicKey)

		rows, err := config.DB.QueryContext(ctx, "SELECT hostname, created_at FROM trusted_public_keys WHERE keytype='ed25519' AND key = $1", longLivedPublicKey)
		if err != nil {
			return errors.Wrap(err, "Could not fetch trusted public keys")
		}
		if !rows.Next() {
			return errors.New("No matching public key to provided private key found")
		}
		var keyHostname string
		var keyCreatedAt time.Time
		err = rows.Scan(&keyHostname, &keyCreatedAt)
		if err != nil {
			return errors.Wrap(err, "Could not read public keys from database")
		}
		logger.G(ctx).WithFields(map[string]interface{}{
			"hostname":  keyHostname,
			"createdAt": keyCreatedAt,
		}).Debug("Found matching public key for private key")

		row := config.DB.QueryRowContext(ctx, "SELECT nextval('worker_id')")
		err = row.Scan(&vpc.workerID)
		if err != nil {
			return fmt.Errorf("Unable to get worker ID: %w", err)
		}
		vpc.workerID &= (1 << 12) - 1
		logger.G(ctx).WithField("workerID", vpc.workerID).Info("Got worker ID")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return errors.Wrap(err, "Could not generate host key")
	}
	hostPublicKeySignature := ed25519.Sign(ed25519key, publicKey)

	vpc.authoritativePublicKey = ed25519key.Public().(ed25519.PublicKey)
	vpc.hostPrivateKey = privateKey
	vpc.hostPublicKey = publicKey
	vpc.hostPublicKeySignature = hostPublicKeySignature

	hc := &healthcheck{}

	m := cmux.New(config.Listener)

	serve := func(listener net.Listener, wrapwithAuth bool, options ...grpc.ServerOption) error {
		grpcServerOptions := []grpc.ServerOption{
			grpc.StatsHandler(&ocgrpc.ServerHandler{}),
			grpc_middleware.WithUnaryServerChain(
				grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
				grpc_logrus.UnaryServerInterceptor(logrusEntry),
				grpc_auth.UnaryServerInterceptor(vpc.authFunc),
				services.UnaryMetricsHandler,
			),
			grpc_middleware.WithStreamServerChain(
				grpc_ctxtags.StreamServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
				grpc_logrus.StreamServerInterceptor(logrusEntry),
			),
			grpc.KeepaliveParams(keepalive.ServerParameters{
				MaxConnectionIdle: 5 * time.Minute,
			}),
		}
		grpcServer := grpc.NewServer(append(grpcServerOptions, options...)...)

		grpc_health_v1.RegisterHealthServer(grpcServer, hc)
		if wrapwithAuth {
			vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, &titusVPCAgentServiceAuthFuncOverride{vpc})
		} else {
			vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, vpc)
		}
		titus.RegisterUserIPServiceServer(grpcServer, vpc)
		titus.RegisterValidatorIPServiceServer(grpcServer, vpc)
		titus.RegisterTitusAgentVPCInformationServiceServer(grpcServer, vpc)
		titus.RegisterTitusAgentSecurityGroupServiceServer(grpcServer, vpc)

		reflection.Register(grpcServer)
		group.Go(func() error {
			<-ctx.Done()
			logger.G(ctx).Info("GRPC Server shutting down gracefully")
			time.AfterFunc(30*time.Second, func() {
				logger.G(ctx).Warning("GRPC Server force shutting down")
				grpcServer.Stop()
			})
			cancel()
			grpcServer.GracefulStop()
			return nil
		})

		return grpcServer.Serve(listener)
	}

	logger.G(ctx).Info("GRPC Server starting up")

	sslListener := m.Match(cmux.TLS())
	http1Listener := m.Match(cmux.HTTP1Fast())
	anyListener := m.Match(cmux.Any())

	if config.TLSConfig != nil {
		c := credentials.NewTLS(config.TLSConfig)
		group.Go(func() error { return serve(sslListener, true, grpc.Creds(c)) })
	}

	group.Go(func() error { return serve(anyListener, false) })
	group.Go(func() error { return http.Serve(http1Listener, hc) })
	group.Go(m.Serve)
	if !config.disableRouteCache {
		group.Go(func() error {
			vpc.monitorRouteTableLoop(ctx)
			return nil
		})
	}

	taskLoops := vpc.getTaskLoops()
	enabledTaskLoops := sets.NewString(config.EnabledTaskLoops...)
	for idx := range taskLoops {
		task := taskLoops[idx]
		if enabledTaskLoops.Has(task.taskName) {
			logger.G(ctx).WithField("task", task.taskName).Info("Starting task loop")
			group.Go(func() error {
				return vpc.taskLoop(ctx, config.ReconcileInterval, task.taskName, task.itemLister, task.workFunc)
			})
		} else {
			logger.G(ctx).WithField("task", task.taskName).Info("Task loop disabled")
		}
	}

	longLivedTasks := vpc.getLongLivedTasks()
	enabledLongLivedTasks := sets.NewString(config.EnabledLongLivedTasks...)
	for idx := range longLivedTasks {
		task := longLivedTasks[idx]
		if enabledLongLivedTasks.Has(task.taskName) {
			logger.G(ctx).WithField("task", task.taskName).Info("Starting task")
			group.Go(func() error {
				return vpc.runFunctionUnderLongLivedLock(ctx, task.taskName, task.itemLister, task.workFunc)
			})
		} else {
			logger.G(ctx).WithField("task", task.taskName).Info("Task disabled")
		}
	}

	err = group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type longLivedTask struct {
	taskName   string
	workFunc   workFunc
	itemLister itemLister
}

func (vpcService *vpcService) getLongLivedTasks() []longLivedTask {
	return []longLivedTask{
		vpcService.reconcileBranchENIAttachmentsLongLivedTask(),
		{
			taskName:   "gc_enis2",
			itemLister: vpcService.getBranchENIRegionAccounts,
			workFunc:   vpcService.doGCAttachedENIsLoop,
		},
		vpcService.deleteExcessBranchesLongLivedTask(),
		{
			taskName:   "detach_unused_branch_eni",
			itemLister: vpcService.getSubnets,
			workFunc:   vpcService.detatchUnusedBranchENILoop,
		},
		{
			taskName:   "delete_failed_assignments",
			itemLister: nilItemEnumerator,
			workFunc:   vpcService.deleteFailedAssignments,
		},
		vpcService.reconcileBranchENIsLongLivedTask(),
		vpcService.associateActionWorker().longLivedTask(),
		vpcService.disassociateActionWorker().longLivedTask(),
		vpcService.reconcileTrunkENIsLongLivedTask(),
		vpcService.reconcileSecurityGroupsLongLivedTask(),
		vpcService.reconcileSubnetCIDRReservationsLongLivedTask(),
	}
}

func GetLongLivedTaskNames() []string {
	s := &vpcService{}
	tasks := s.getLongLivedTasks()
	ret := make([]string, len(tasks))
	for idx := range tasks {
		ret[idx] = tasks[idx].taskName
	}
	return ret
}

type taskLoop struct {
	taskName   string
	workFunc   taskLoopWorkFunc
	itemLister itemLister
}

func (vpcService *vpcService) getTaskLoops() []taskLoop {
	return []taskLoop{
		{
			// This was bumped to subnets2 because the "new" version adds prefixes.
			taskName:   "subnets2",
			itemLister: vpcService.getRegionAccounts,
			workFunc:   vpcService.reconcileSubnetsForRegionAccount,
		},
		{
			taskName:   "elastic_ip",
			itemLister: vpcService.getRegionAccounts,
			workFunc:   vpcService.reconcileEIPsForRegionAccount,
		},
		{
			taskName:   "availability_zone",
			itemLister: vpcService.getAllRegionAccounts,
			workFunc:   vpcService.reconcileAvailabilityZonesRegionAccount,
		},
		{
			taskName:   "last_used_ip_pruner",
			itemLister: nilItemEnumerator,
			workFunc:   vpcService.pruneLastUsedIPAddresses,
		},
	}
}

func GetTaskLoopTaskNames() []string {
	s := &vpcService{}
	tasks := s.getTaskLoops()
	ret := make([]string, len(tasks))
	for idx := range tasks {
		ret[idx] = tasks[idx].taskName
	}
	return ret
}

type healthcheck struct {
}

func (hc *healthcheck) Check(ctx context.Context, r *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	// For now, this is a noop, because the "perspective" matters
	switch r.Service {
	case "com.netflix.titus.executor.vpc.TitusAgentVPCService", "grpc.reflection.v1alpha.ServerReflection":
	default:
		return nil, status.Errorf(codes.NotFound, "Service %q not found", r.Service)
	}

	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

func (hc *healthcheck) Watch(*grpc_health_v1.HealthCheckRequest, grpc_health_v1.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Streaming healthchecks are not yet implemented")
}

func (healthcheck) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO Write healthcheck
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Success\n"))
}
