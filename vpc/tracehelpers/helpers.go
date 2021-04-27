package tracehelpers

import (
	"context"
	"errors"
	"fmt"

	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func SetStatus(err error, span *trace.Span) {
	if err == nil {
		span.SetStatus(trace.Status{
			Code: trace.StatusCodeOK,
		})
		return
	}

	if grpcStatus, ok := status.FromError(err); ok {
		status := trace.Status{
			Code:    int32(grpcStatus.Code()),
			Message: grpcStatus.Message(),
		}

		span.SetStatus(status)
		return
	}

	code := trace.StatusCodeUnknown
	if errors.Is(err, context.Canceled) {
		code = trace.StatusCodeCancelled
	} else if errors.Is(err, context.DeadlineExceeded) {
		code = trace.StatusCodeDeadlineExceeded
	}

	span.SetStatus(trace.Status{
		Code:    int32(code),
		Message: err.Error(),
	})
}

type GRPCError interface {
	error
	GRPCStatus() *status.Status
}

type grpcError struct {
	err  error
	code codes.Code
}

func (g *grpcError) Error() string {
	return fmt.Sprintf("GRPC Error (code: %s): %s",
		g.code.String(), g.err.Error())
}

func (g *grpcError) Unwrap() error {
	return g.err
}

func (g *grpcError) GRPCStatus() *status.Status {
	return status.New(g.code, g.err.Error())
}

func WithGRPCStatusCode(err error, code codes.Code) GRPCError {
	return &grpcError{
		err:  err,
		code: code,
	}
}
