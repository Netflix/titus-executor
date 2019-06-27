package service

import (
	"testing"

	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"
)

func TestConvertCode(t *testing.T) {
	assert.Assert(t, convertCode(codes.OK) == trace.StatusCodeOK)
	assert.Assert(t, convertCode(codes.Unknown) == trace.StatusCodeUnknown)
	assert.Assert(t, convertCode(codes.NotFound) == trace.StatusCodeNotFound)
}

func TestTraceStatusFromError(t *testing.T) {
	assert.Assert(t, traceStatusFromError(nil) == trace.Status{Code: trace.StatusCodeOK})
	assert.Assert(t, traceStatusFromError(status.Error(codes.NotFound, "foo")) == trace.Status{Message: "foo", Code: trace.StatusCodeNotFound})
}
