package tracehelpers

import (
	"context"

	"go.opencensus.io/trace"
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
	switch err {
	case context.Canceled:
		code = trace.StatusCodeCancelled
	case context.DeadlineExceeded:
		code = trace.StatusCodeDeadlineExceeded
	}

	span.SetStatus(trace.Status{
		Code:    int32(code),
		Message: err.Error(),
	})
}
