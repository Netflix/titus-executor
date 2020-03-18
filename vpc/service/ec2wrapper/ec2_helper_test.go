package ec2wrapper

import (
	"context"

	"github.com/pkg/errors"

	"testing"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"
)

type collectingExporter struct {
	data []*trace.SpanData
}

func (c *collectingExporter) ExportSpan(s *trace.SpanData) {
	c.data = append(c.data, s)
}

func TestBasicErrorHandler(t *testing.T) {
	exporter := &collectingExporter{}

	trace.RegisterExporter(exporter)
	defer trace.UnregisterExporter(exporter)

	ctx := context.Background()
	ctx, span := trace.StartSpan(ctx, "foo", trace.WithSampler(trace.AlwaysSample()))
	_ = ctx
	err := awserr.New("Client.RequestLimitExceeded", "My message", errors.New("Original error"))
	err2 := HandleEC2Error(err, span)
	span.End()

	s, ok := status.FromError(err2)
	assert.Assert(t, ok)
	assert.Equal(t, s.Code(), codes.ResourceExhausted)
	t.Log(exporter.data)
	assert.Assert(t, len(exporter.data) == 1)
	assert.Assert(t, exporter.data[0].Code == trace.StatusCodeResourceExhausted)
}

func TestWrappedErrorHandling(t *testing.T) {
	exporter := &collectingExporter{}

	trace.RegisterExporter(exporter)
	defer trace.UnregisterExporter(exporter)

	ctx := context.Background()
	ctx, span := trace.StartSpan(ctx, "foo", trace.WithSampler(trace.AlwaysSample()))
	_ = ctx
	var err error = awserr.New("Client.RequestLimitExceeded", "My message", errors.New("Original error"))
	err = errors.Wrap(err, "Something, something AWS")
	err2 := HandleEC2Error(err, span)
	span.End()

	s, ok := status.FromError(err2)
	assert.Assert(t, ok)
	assert.Equal(t, s.Code(), codes.ResourceExhausted)
	t.Log(exporter.data)
	assert.Assert(t, len(exporter.data) == 1)
	assert.Assert(t, exporter.data[0].Code == trace.StatusCodeResourceExhausted)
}
