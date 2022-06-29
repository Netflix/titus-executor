package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"contrib.go.opencensus.io/exporter/zipkin"
	"github.com/Netflix/titus-executor/services"
	"github.com/sirupsen/logrus"

	"github.com/Netflix/titus-executor/vpc/service/db/wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"go.opencensus.io/trace"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/metrics"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	ccache "github.com/karlseguin/ccache/v2"
	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
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

const (
	// Update dynamic configs every 5 minutes
	dynamicConfigUpdateInterval = 5 * time.Minute
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

	db *sql.DB

	config                 *Config
	dynamicConfig          *DynamicConfig
	authoritativePublicKey ed25519.PublicKey
	hostPublicKeySignature []byte
	hostPrivateKey         ed25519.PrivateKey
	hostPublicKey          ed25519.PublicKey

	refreshLock *semaphore.Weighted

	dbRateLimiter *rate.Limiter

	trunkTracker              *trunkTrackerCache
	invalidSecurityGroupCache *ccache.Cache

	concurrentRequests *semaphore.Weighted

	routesCache sync.Map

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

func (vpcService *vpcService) serve(
	logrusEntry *logrus.Entry,
	listener net.Listener,
	wrapwithAuth bool,
	hc *healthcheck,
	addShutdownFunc func(*grpc.Server),
	options ...grpc.ServerOption) error {
	grpcServerOptions := []grpc.ServerOption{
		grpc.StatsHandler(&ocgrpc.ServerHandler{}),
		grpc_middleware.WithUnaryServerChain(
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
			grpc_auth.UnaryServerInterceptor(vpcService.authFunc),
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
		vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, &titusVPCAgentServiceAuthFuncOverride{vpcService})
	} else {
		vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, vpcService)
	}
	titus.RegisterUserIPServiceServer(grpcServer, vpcService)
	titus.RegisterValidatorIPServiceServer(grpcServer, vpcService)
	titus.RegisterTitusAgentVPCInformationServiceServer(grpcServer, vpcService)
	titus.RegisterTitusAgentSecurityGroupServiceServer(grpcServer, vpcService)

	reflection.Register(grpcServer)
	addShutdownFunc(grpcServer)
	return grpcServer.Serve(listener)
}

func newVpcService(ctx context.Context, config *Config) (*vpcService, error) {
	// Make sure all configs are valid
	err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, errors.Wrap(err, "Cannot get hostname")
	}

	var dbConn *sql.DB
	if config.DBURL != "" {
		dburl, conn, err := wrapper.NewConnection(ctx, config.DBURL, config.MaxIdleConnections, config.MaxOpenConnections)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to connect to db")
		}
		config.DBURL = dburl
		dbConn = conn

		needsMigration, err := db.NeedsMigration(ctx, dbConn)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to check if the DB needs migration")
		}
		if needsMigration {
			logger.G(ctx).Fatal("Cannot startup, need to run database migrations")
		}
	}

	// TODO: actually validate this
	ed25519key := ed25519.NewKeyFromSeed(config.Key.GetEd25519Key().Rfc8032Key)
	if dbConn != nil {
		longLivedPublicKey := ed25519key.Public().(ed25519.PublicKey)

		rows, err := dbConn.QueryContext(ctx, "SELECT hostname, created_at FROM trusted_public_keys WHERE keytype='ed25519' AND key = $1", longLivedPublicKey)
		if err != nil {
			return nil, errors.Wrap(err, "Could not fetch trusted public keys")
		}
		if !rows.Next() {
			return nil, errors.New("No matching public key to provided private key found")
		}
		var keyHostname string
		var keyCreatedAt time.Time
		err = rows.Scan(&keyHostname, &keyCreatedAt)
		if err != nil {
			return nil, errors.Wrap(err, "Could not read public keys from database")
		}
		logger.G(ctx).WithFields(map[string]interface{}{
			"hostname":  keyHostname,
			"createdAt": keyCreatedAt,
		}).Debug("Found matching public key for private key")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, errors.Wrap(err, "Could not generate host key")
	}
	hostPublicKeySignature := ed25519.Sign(ed25519key, publicKey)

	return &vpcService{
		hostname: hostname,
		ec2:      ec2wrapper.NewEC2SessionManager(config.WorkerRole),
		db:       dbConn,

		config:                 config,
		authoritativePublicKey: ed25519key.Public().(ed25519.PublicKey),
		hostPrivateKey:         privateKey,
		hostPublicKey:          publicKey,
		hostPublicKeySignature: hostPublicKeySignature,

		refreshLock: semaphore.NewWeighted(config.MaxConcurrentRefresh),

		dbRateLimiter: rate.NewLimiter(1000, 1),

		trunkTracker:              newTrunkTrackerCache(),
		invalidSecurityGroupCache: ccache.New(ccache.Configure()),

		concurrentRequests: semaphore.NewWeighted(int64(config.MaxConcurrentRequests)),
	}, nil
}

func validateConfig(config *Config) error {
	if config.TrunkNetworkInterfaceDescription == "" {
		return errors.New("Trunk interface description must be non-empty")
	}

	if config.BranchNetworkInterfaceDescription == "" {
		return errors.New("Branch interface description must be non-empty")
	}

	if config.WorkerRole == "" {
		return errors.New("The worker role must be non-empty")
	}
	return nil
}

func Run(ctx context.Context, config *Config, address string) error {
	vpcService, err := newVpcService(ctx, config)
	if err != nil {
		return errors.Wrap(err, "Failed to create VPC service")
	}
	return vpcService.run(ctx, address)
}

func (vpcService *vpcService) setupInstrument(ctx context.Context) error {
	if vpcService.db != nil {
		collector := metrics.NewCollector(ctx, vpcService.db, &metrics.CollectorConfig{
			TableMetricsInterval: vpcService.config.TableMetricsInterval})

		// Start collecting metrics
		collector.Start()
	}

	if vpcService.config.ZipkinURL != "" {
		reporter := zipkinHTTP.NewReporter(vpcService.config.ZipkinURL,
			zipkinHTTP.BatchInterval(time.Second*5),
			zipkinHTTP.BatchSize(1000),
			zipkinHTTP.MaxBacklog(100000),
		)
		endpoint, err := openzipkin.NewEndpoint("titus-vpc-service", vpcService.hostname)
		if err != nil {
			return errors.Wrap(err, "Failed to create the local zipkinEndpoint")
		}
		logger.G(ctx).WithField("endpoint", endpoint).WithField("url", vpcService.config.ZipkinURL).Info("Setting up tracing")
		trace.RegisterExporter(zipkin.NewExporter(reporter, endpoint))
	}
	return nil
}

func (vpcService *vpcService) run(ctx context.Context, address string) error {
	if vpcService.config.DynamicConfigURL != "" {
		vpcService.dynamicConfig = NewDynamicConfig()
		vpcService.dynamicConfig.Start(ctx, dynamicConfigUpdateInterval, vpcService.config.DynamicConfigURL)
	}

	err := vpcService.setupInstrument(ctx)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)

	logrusEntry := logger.G(ctx).WithField("origin", "grpc")
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)

	if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrap(err, "Could not setup listener")
	}
	defer listener.Close()
	logger.G(ctx).WithField("address", listener.Addr().String()).Info("Listening")

	m := cmux.New(listener)

	logger.G(ctx).Info("GRPC Server starting up")

	sslListener := m.Match(cmux.TLS())
	http1Listener := m.Match(cmux.HTTP1Fast())
	anyListener := m.Match(cmux.Any())

	addShutdownFunc := func(grpcServer *grpc.Server) {
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
	}

	hc := &healthcheck{}
	if vpcService.config.TLSConfig != nil {
		c := credentials.NewTLS(vpcService.config.TLSConfig)
		group.Go(func() error {
			return vpcService.serve(logrusEntry, sslListener, true, hc, addShutdownFunc, grpc.Creds(c))
		})
	}

	group.Go(func() error { return vpcService.serve(logrusEntry, anyListener, false, hc, addShutdownFunc) })
	group.Go(func() error { return http.Serve(http1Listener, hc) })
	group.Go(m.Serve)
	if !vpcService.config.disableRouteCache {
		group.Go(func() error {
			vpcService.monitorRouteTableLoop(ctx)
			return nil
		})
	}

	taskLoops := vpcService.getTaskLoops()
	enabledTaskLoops := sets.NewString(vpcService.config.EnabledTaskLoops...)
	for idx := range taskLoops {
		task := taskLoops[idx]
		if enabledTaskLoops.Has(task.taskName) {
			logger.G(ctx).WithField("task", task.taskName).Info("Starting task loop")
			group.Go(func() error {
				return vpcService.taskLoop(ctx, vpcService.config.ReconcileInterval, task.taskName, task.itemLister, task.workFunc)
			})
		} else {
			logger.G(ctx).WithField("task", task.taskName).Info("Task loop disabled")
		}
	}

	longLivedTasks := vpcService.getLongLivedTasks()
	enabledLongLivedTasks := sets.NewString(vpcService.config.EnabledLongLivedTasks...)
	for idx := range longLivedTasks {
		task := longLivedTasks[idx]
		if enabledLongLivedTasks.Has(task.taskName) {
			logger.G(ctx).WithField("task", task.taskName).Info("Starting task")
			group.Go(func() error {
				return vpcService.runFunctionUnderLongLivedLock(ctx, task.taskName, task.itemLister, task.workFunc)
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
		{
			taskName:   "subnets",
			itemLister: vpcService.getRegionAccounts,
			workFunc:   vpcService.doReconcileSubnetsForRegionAccountLoop,
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
	s := &vpcService{config: &Config{}}
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
	s := &vpcService{config: &Config{}}
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
