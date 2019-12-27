package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"google.golang.org/grpc/keepalive"

	"google.golang.org/grpc/credentials"

	"golang.org/x/sync/semaphore"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/pkg/errors"
	"github.com/soheilhy/cmux"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

var (
	methodTag     = tag.MustNewKey("method")
	returnCodeTag = tag.MustNewKey("returnCode")
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
			TagKeys:     []tag.Key{methodTag, returnCodeTag},
		},
		&view.View{
			Name:        grpcRequestNs.Name(),
			Description: grpcRequestNs.Description(),
			Measure:     grpcRequestNs,
			Aggregation: view.Distribution(),
			TagKeys:     []tag.Key{methodTag, returnCodeTag},
		}); err != nil {
		panic(err)
	}
}

type vpcService struct {
	// We hope this is globally unique
	hostname string
	ec2      *ec2wrapper.EC2SessionManager

	dummyInterfaceLock sync.Mutex
	dummyInterfaces    map[string]*ec2.NetworkInterface

	db *sql.DB

	authoritativePublicKey ed25519.PublicKey
	hostPublicKeySignature []byte
	hostPrivateKey         ed25519.PrivateKey
	hostPublicKey          ed25519.PublicKey

	gcTimeout       time.Duration
	refreshInterval time.Duration

	refreshLock *semaphore.Weighted

	TitusAgentCACertPool *x509.CertPool
}

func unaryMetricsHandler(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := tag.New(ctx, tag.Upsert(methodTag, info.FullMethod))
	if err != nil {
		return nil, err
	}

	start := time.Now()
	result, err := handler(ctx, req)

	st, _ := status.FromError(err)
	duration := time.Since(start)
	l := logger.G(ctx).WithField("method", info.FullMethod).WithField("statusCode", st.Code().String()).WithField("duration", duration.String())
	fun := l.Info
	if err != nil {
		fun = l.WithError(err).Warn
	}

	fun("Finished unary call")

	ctx2, err2 := tag.New(ctx, tag.Upsert(returnCodeTag, st.Code().String()))
	if err2 != nil {
		return result, err
	}

	stats.Record(ctx2, grpcRequestNs.M(duration.Nanoseconds()))
	stats.Record(ctx2, grpcRequest.M(1))

	return result, err
}

type Config struct {
	Listener             net.Listener
	DB                   *sql.DB
	Key                  vpcapi.PrivateKey
	MaxConcurrentRefresh int64
	GCTimeout            time.Duration
	ReconcileInterval    time.Duration
	RefreshInterval      time.Duration
	TLSConfig            *tls.Config
	TitusAgentCACertPool *x509.CertPool
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

	vpc := &vpcService{
		hostname:        hostname,
		ec2:             ec2wrapper.NewEC2SessionManager(),
		dummyInterfaces: make(map[string]*ec2.NetworkInterface),
		db:              config.DB,

		gcTimeout:       config.GCTimeout,
		refreshInterval: config.RefreshInterval,

		refreshLock: semaphore.NewWeighted(config.MaxConcurrentRefresh),

		TitusAgentCACertPool: config.TitusAgentCACertPool,
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
				unaryMetricsHandler,
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
	group.Go(func() error {
		return vpc.taskLoop(ctx, config.ReconcileInterval, "reconcile_branch_enis", vpc.reconcileBranchENIsForRegionAccount)
	})
	group.Go(func() error {
		return vpc.taskLoop(ctx, config.ReconcileInterval, "delete_dangling_trunks", vpc.deleteDanglingTrunksForRegionAccount)
	})
	err = group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
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
