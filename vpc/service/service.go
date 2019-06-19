package service

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"

	"go.opencensus.io/stats/view"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/soheilhy/cmux"
	"go.opencensus.io/plugin/ocgrpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	ListenAddr string
	Metrics    *statsd.Client
}

func (server *Server) Run(ctx context.Context, listener net.Listener) error {
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

	vpc := &vpcService{
		ec2: ec2wrapper.NewEC2SessionManager(),
	}
	vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, vpc)
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
	group.Go(func() error { return http.Serve(http1Listener, &healthcheck{}) })
	group.Go(m.Serve)

	err := group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type healthcheck struct {
}

func (healthcheck) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO Write healthcheck
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Success\n"))
}
