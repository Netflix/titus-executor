package ec2wrapper

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/hashicorp/go-multierror"
	"go.opencensus.io/trace"
)

type hedgeResponse struct {
	output interface{}
	err    error
}

func hedger(ctx context.Context, rq func(context.Context) (interface{}, error), delay time.Duration, responseChannel chan *hedgeResponse) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "hedger")
	defer span.End()
	hedge := false
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		hedge = true
	}
	span.AddAttributes(trace.BoolAttribute("hedge", hedge))
	output, err := rq(ctx)
	tracehelpers.SetStatus(err, span)
	select {
	case responseChannel <- &hedgeResponse{
		err:    err,
		output: output,
	}:
	case <-ctx.Done():
	}
}
func hedge(ctx context.Context, rq func(context.Context) (interface{}, error), delays []time.Duration) (interface{}, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "hedge")
	defer span.End()

	responseChannel := make(chan *hedgeResponse, len(delays))
	for idx := range delays {
		go hedger(ctx, rq, delays[idx], responseChannel)
	}
	responses := []*hedgeResponse{}
	for len(responses) < len(delays) {
		select {
		case <-ctx.Done():
			goto out
		case response := <-responseChannel:
			if response.err == nil {
				return response.output, response.err
			}
			responses = append(responses, response)
		}
	}
out:
	if len(responses) == 0 {
		return nil, ctx.Err()
	}
	var err *multierror.Error
	for _, response := range responses {
		err = multierror.Append(err, response.err)
	}
	return nil, err
}
