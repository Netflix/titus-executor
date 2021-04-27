package service

import (
	"context"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (vpcService *vpcService) ValidateAllocationParameters(ctx context.Context, req *titus.ParametersValidationRequest) (*titus.ParametersValidationResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "ValidateAllocationParameters")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	_ = ctx

	err := status.Error(codes.Unimplemented, "Call not yet implemented")
	tracehelpers.SetStatus(err, span)
	return nil, err
}
