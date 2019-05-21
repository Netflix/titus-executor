package service

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/aws/aws-sdk-go/aws/session"

	"github.com/DataDog/datadog-go/statsd"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	ListenAddr string
	Metrics    *statsd.Client
}

func (server *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", server.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	logrusEntry := logger.G(ctx).WithField("origin", "grpc")
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)
	fmt.Println(logrus.StandardLogger().Level)

	grpcServer := grpc.NewServer(
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

	sess := session.Must(session.NewSession())

	vpc := &vpcService{
		metrics: server.Metrics,
		session: sess,
	}
	vpcapi.RegisterTitusAgentVPCServiceServer(grpcServer, vpc)
	reflection.Register(grpcServer)

	go func() {
		<-ctx.Done()
		time.AfterFunc(30*time.Second, grpcServer.Stop)
		grpcServer.GracefulStop()
	}()
	logger.G(ctx).Info("GRPC Server starting up")

	return grpcServer.Serve(listener)
}
