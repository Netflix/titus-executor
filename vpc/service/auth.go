package service

import (
	"context"

	"github.com/Netflix/titus-executor/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
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
	// TODO: Authn happens via the normal TLS verification, here is where
	// we can add additional verification, like looking at the CN.
	return ctx, nil
}
