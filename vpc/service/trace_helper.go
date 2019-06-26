package service

import (
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Converts GRPC Errors to opencensus statuses (or tries to)
func traceStatusFromError(err error) trace.Status {
	s := status.Convert(err)
	return trace.Status{
		Code:    convertCode(s.Code()),
		Message: s.Message(),
	}
}

func convertCode(code codes.Code) int32 {
	// These codes are actually the same as the grpc codes
	return int32(code)
}
