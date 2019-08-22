package service

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/soheilhy/cmux"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type vpcService struct {
	// We hope this is globally unique
	hostname string
	ec2      ec2wrapper.EC2SessionManager

	dummyInterfaceLock     sync.Mutex
	dummyInterfaceSessions map[string]ec2wrapper.EC2NetworkInterfaceSession
	dummyInterfaces        map[string]*ec2.NetworkInterface

	conn *sql.DB

	authoritativePublicKey ed25519.PublicKey
	hostPublicKeySignature []byte
	hostPrivateKey         ed25519.PrivateKey
	hostPublicKey          ed25519.PublicKey
}

func Run(ctx context.Context, listener net.Listener, conn *sql.DB, key vpcapi.PrivateKey) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)

	logrusEntry := logger.G(ctx).WithField("origin", "grpc")
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)

	if err := view.Register(ocgrpc.DefaultServerViews...); err != nil {
		return err
	}

	grpcServer := grpc.NewServer(
		grpc.StatsHandler(&ocgrpc.ServerHandler{}),
		grpc_middleware.WithUnaryServerChain(
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_ctxtags.StreamServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_logrus.StreamServerInterceptor(logrusEntry),
		),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     30 * time.Second,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  45 * time.Second,
		}))
	hostname, err := os.Hostname()
	if err != nil {
		return errors.Wrap(err, "Cannot get hostname")
	}

	// TODO: actually validate this
	ed25519key := ed25519.NewKeyFromSeed(key.GetEd25519Key().Rfc8032Key)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return errors.Wrap(err, "Could not generate host key")
	}
	hostPublicKeySignature := ed25519.Sign(ed25519key, publicKey)

	vpc := &vpcService{
		hostname:               hostname,
		ec2:                    ec2wrapper.NewEC2SessionManager(),
		dummyInterfaceSessions: make(map[string]ec2wrapper.EC2NetworkInterfaceSession),
		dummyInterfaces:        make(map[string]*ec2.NetworkInterface),
		conn:                   conn,

		authoritativePublicKey: ed25519key.Public().(ed25519.PublicKey),
		hostPrivateKey:         privateKey,
		hostPublicKey:          publicKey,
		hostPublicKeySignature: hostPublicKeySignature,
	}

	hc := &healthcheck{}
	grpc_health_v1.RegisterHealthServer(grpcServer, hc)
	vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, vpc)
	titus.RegisterUserIPServiceServer(grpcServer, vpc)

	reflection.Register(grpcServer)

	m := cmux.New(listener)

	go func() {
		<-ctx.Done()
		logger.G(ctx).Info("GRPC Server shutting down")
		time.AfterFunc(30*time.Second, func() {
			logger.G(ctx).Warning("GRPC Server force shutting down")
			grpcServer.Stop()
		})
		cancel()
		grpcServer.GracefulStop()
	}()
	logger.G(ctx).Info("GRPC Server starting up")

	http1Listener := m.Match(cmux.HTTP1Fast())
	anyListener := m.Match(cmux.Any())

	group.Go(func() error { return grpcServer.Serve(anyListener) })
	group.Go(func() error { return http.Serve(http1Listener, hc) })
	group.Go(m.Serve)

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
