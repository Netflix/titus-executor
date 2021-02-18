package services

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"go.opencensus.io/tag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	MethodTag     = tag.MustNewKey("method")
	ReturnCodeTag = tag.MustNewKey("returnCode")
)

func UnaryMetricsHandler(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	ctx, err := tag.New(ctx, tag.Upsert(MethodTag, info.FullMethod))
	if err != nil {
		return nil, err
	}

	start := time.Now()
	result, err := handler(ctx, req)

	// TODO: Implement error unwrapping here to catch wrapped errors, so try to unwrap
	// into an error which implements `GRPCStatus` before setting status From error
	st, _ := status.FromError(err)
	duration := time.Since(start)
	l := logger.G(ctx).WithField("method", info.FullMethod).WithField("statusCode", st.Code().String()).WithField("duration", duration.String())
	fun := l.Info
	if err != nil {
		fun = l.WithError(err).Warn
	}

	fun("Finished unary call")

	_, err2 := tag.New(ctx, tag.Upsert(ReturnCodeTag, st.Code().String()))
	if err2 != nil {
		return result, err
	}

	return result, err
}
