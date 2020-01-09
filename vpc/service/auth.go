package service

import (
	"context"
	x509 "crypto/x509"
	"fmt"

	"github.com/pkg/errors"

	"google.golang.org/grpc/credentials"

	"github.com/Netflix/titus-executor/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var (
	errNoAuth = errors.New("No authentication")
)

func (*vpcService) authFunc(ctx context.Context) (context.Context, error) {
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
	return ctx, nil
}

type titusVPCAgentServiceAuthFuncOverride struct {
	*vpcService
}

func (vpcService *titusVPCAgentServiceAuthFuncOverride) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Internal, "Could not retrieve peer from context")
	}
	if peer.AuthInfo == nil {
		// TODO: Log this
		return ctx, errNoAuth
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return ctx, fmt.Errorf("Received unexpected authentication type: %s", peer.AuthInfo.AuthType())
	}
	sv := tlsInfo.GetSecurityValue().(*credentials.TLSChannelzSecurityValue)
	cert, err := x509.ParseCertificate(sv.RemoteCertificate)
	if err != nil {
		return ctx, errors.Wrap(err, "Cannot parse remote certificate")
	}
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     vpcService.TitusAgentCACertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, errors.Wrap(err, "Unable to verify client cert")
	}
	return ctx, nil
}
