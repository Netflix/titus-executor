package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/metadataserver"
	iamapi "github.com/Netflix/titus-executor/metadataserver/api"
	"github.com/Netflix/titus-executor/services"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang/protobuf/ptypes"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/soheilhy/cmux"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/trace"
	errgroup "golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	sessionLifetime = 3600
)

type Config struct {
	Listener        net.Listener
	OpenPolicyAgent string
	ClientCA        string
	Region          string
	SSLKey          string
	SSLCert         string
}

type service struct {
	certficiateLock sync.RWMutex
	certficate      *tls.Certificate
	sslKey          string
	sslCert         string
	sts             *sts.STS
	iamapi.UnimplementedIAMServer
}

func (s *service) AssumeRole(ctx context.Context, request *iamapi.AssumeRoleRequest) (*iamapi.AssumeRoleResponse, error) {
	// TODO: Rate limiting, timeouts, etc..
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssumeRole")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("roleARN", request.RoleARN),
		trace.StringAttribute("taskId", request.TaskId),
	)
	ctx = logger.WithField(ctx, "arn", request.RoleARN)
	logger.G(ctx).Debug("Starting role assumption")

	sessionName := metadataserver.GenerateSessionName(request.TaskId)
	ctx = logger.WithField(ctx, "sessionName", sessionName)
	span.AddAttributes(trace.StringAttribute("sessionName", sessionName))

	role, err := s.sts.AssumeRoleWithContext(ctx, &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(sessionLifetime),
		RoleArn:         aws.String(request.RoleARN),
		RoleSessionName: &sessionName,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not assume role")
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	logger.G(ctx).WithField("accesskey", aws.StringValue(role.Credentials.AccessKeyId)).Info("Successfully assumed role")
	expiration, err := ptypes.TimestampProto(aws.TimeValue(role.Credentials.Expiration))
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not convert AWS credential expiration time into real time")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &iamapi.AssumeRoleResponse{
		AssumedRoleUser: &iamapi.AssumeRoleResponse_AssumedRoleUser{
			AssumedRoleId: aws.StringValue(role.AssumedRoleUser.AssumedRoleId),
			Arn:           aws.StringValue(role.AssumedRoleUser.Arn),
		},
		Credentials: &iamapi.AssumeRoleResponse_Credentials{
			SecretAccessKey: aws.StringValue(role.Credentials.SecretAccessKey),
			SessionToken:    aws.StringValue(role.Credentials.SessionToken),
			Expiration:      expiration,
			AccessKeyId:     aws.StringValue(role.Credentials.AccessKeyId),
		},
	}, nil
}

func (s *service) Check(ctx context.Context, request *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	panic("implement me")
}

func (s *service) Watch(request *grpc_health_v1.HealthCheckRequest, server grpc_health_v1.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "Streaming healthchecks are not yet implemented")
}

func (s *service) authFunc(ctx context.Context) (context.Context, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Internal, "Could not retrieve peer from context")
	}
	l := logger.G(ctx)
	if peer.AuthInfo != nil {
		l.Debug("Authenticating peers via authFunc")
	} else {
		l.Debug("not authenticating peers via AuthFuncOverride")
	}
	// TODO: Build an authentication function!

	return ctx, nil
}

func (s *service) healthcheck(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	// TODO: Implement healcheck
	logger.G(ctx).Debug("Received healthcheck")
	_, _ = w.Write([]byte("Available\n"))
}

func (s *service) loadCertificateLoop(ctx context.Context) {
	timer := time.NewTimer(5 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			err := s.loadCertificate(ctx)
			if err != nil {
				logger.G(ctx).WithError(err).Error("Unable to reload certificate")
			}
			timer.Reset(5 * time.Minute)
		}
	}
}

func (s *service) loadCertificate(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(s.sslCert, s.sslKey)
	if err != nil {
		return fmt.Errorf("Could not load certificate: %w", err)
	}
	s.certficiateLock.Lock()
	defer s.certficiateLock.Unlock()
	s.certficate = &cert
	return nil
}

func Run(ctx context.Context, config Config) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)

	logrusEntry := logger.G(ctx).WithField("origin", "grpc")
	grpc_logrus.ReplaceGrpcLogger(logrusEntry)

	svc := &service{
		sslCert: config.SSLCert,
		sslKey:  config.SSLKey,
	}
	s := session.Must(session.NewSession())
	if config.Region != "" {
		endpoint := fmt.Sprintf("sts.%s.amazonaws.com", config.Region)
		stsAwsCfg := aws.NewConfig().
			WithRegion(config.Region).
			WithEndpoint(endpoint)

		c := s.ClientConfig(sts.EndpointsID, stsAwsCfg)
		logger.G(ctx).WithField("region", config.Region).WithField("endpoint", c.Endpoint).Info("Configure STS client with region")
		svc.sts = sts.New(s, stsAwsCfg)
	} else {
		logger.G(ctx).Info("Configure STS client in agnostic manner")
		svc.sts = sts.New(s)
	}

	clientCA, err := ioutil.ReadFile(config.ClientCA)
	if err != nil {
		return fmt.Errorf("Cannot read client CA file %q: %w", config.ClientCA, err)
	}
	certpool := x509.NewCertPool()
	if !certpool.AppendCertsFromPEM(clientCA) {
		return errors.New("No client CAs were able to be loaded")
	}

	if err := svc.loadCertificate(ctx); err != nil {
		return err
	}
	group.Go(func() error {
		svc.loadCertificateLoop(ctx)
		return nil
	})

	creds := credentials.NewTLS(&tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			svc.certficiateLock.RLock()
			defer svc.certficiateLock.RUnlock()
			return svc.certficate, nil
		},
		ClientCAs:  certpool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	})

	m := cmux.New(config.Listener)
	grpcServerOptions := []grpc.ServerOption{
		grpc.StatsHandler(&ocgrpc.ServerHandler{}),
		grpc_middleware.WithUnaryServerChain(
			grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_logrus.UnaryServerInterceptor(logrusEntry),
			grpc_auth.UnaryServerInterceptor(svc.authFunc),
			services.UnaryMetricsHandler,
		),
		grpc_middleware.WithStreamServerChain(
			grpc_ctxtags.StreamServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
			grpc_logrus.StreamServerInterceptor(logrusEntry),
		),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
		}),
		grpc.Creds(creds),
	}

	grpcServer := grpc.NewServer(grpcServerOptions...)

	grpc_health_v1.RegisterHealthServer(grpcServer, svc)
	iamapi.RegisterIAMServer(grpcServer, svc)
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

	logger.G(ctx).Info("GRPC Server starting up")
	http1Listener := m.Match(cmux.HTTP1Fast())
	anyListener := m.Match(cmux.Any())
	group.Go(func() error { return grpcServer.Serve(anyListener) })
	group.Go(func() error {
		return http.Serve(http1Listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx2 := logger.WithLogger(r.Context(), logger.GetLogger(ctx))
			svc.healthcheck(ctx2, w, r)
		}))
	})
	group.Go(m.Serve)

	err = group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}
