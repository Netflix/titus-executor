package ec2wrapper

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"google.golang.org/grpc/status"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/session"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
)

var (
	batchWaitPeriod = stats.Int64("getInterface.waitTimeNs", "How long calls on get interface waited", "ns")
	batchSize       = stats.Int64("getInterface.size", "How many interfaces are normally called at once", "")
	batchLatency    = stats.Int64("getInterface.latencyNs", "How many interfaces are normally called at once", "ns")
)

type batchENIDescriptionRequestResponse struct {
	networkInterfaceID string
	// doneCh is expected to be provided by the user. It is closed when
	// the fields below have been populated
	doneCh chan struct{}
	// Fields populated once the reply is done
	err               error
	networkInterfaces []*ec2.NetworkInterface

	triggerChannel <-chan time.Time

	// triggeredChannel is closed when we accept / begin executing on this request
	triggeredChannel chan struct{}

	span *trace.Span
}

type BatchENIDescriber struct {
	session     *session.Session
	requests    chan *batchENIDescriptionRequestResponse
	maxDeadline time.Duration

	runDescribe func(ctx context.Context, session *session.Session, items []*batchENIDescriptionRequestResponse)
}

// TODO: This currently leaks goroutines.
func NewBatchENIDescriber(ctx context.Context, maxDeadline time.Duration, maxItems int, session *session.Session) *BatchENIDescriber {
	describer := &BatchENIDescriber{
		session:     session,
		requests:    make(chan *batchENIDescriptionRequestResponse, maxItems*10),
		runDescribe: runDescribe,
		maxDeadline: maxDeadline,
	}

	go describer.loop(ctx, maxItems)

	return describer
}

type describerOutput struct {
	err                             error
	describeNetworkInterfacesOutput *ec2.DescribeNetworkInterfacesOutput
}

func describer(ctx context.Context, ec2client *ec2.EC2, enis []*string, describerOutputChan chan *describerOutput, waitBeforeStart time.Duration) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hedge := false
	if waitBeforeStart > 0 {
		timer := time.NewTimer(waitBeforeStart)

		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		hedge = true
	}

	ctx, span := trace.StartSpan(ctx, "describer")
	defer span.End()

	span.AddAttributes(trace.BoolAttribute("hedge", hedge))
	describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: enis,
	})
	err = HandleEC2Error(err, span)

	select {
	case describerOutputChan <- &describerOutput{
		err:                             err,
		describeNetworkInterfacesOutput: describeNetworkInterfacesOutput,
	}:
	case <-ctx.Done():
	}
}

func describeWithHedge(ctx context.Context, ec2client *ec2.EC2, enis []*string) (*ec2.DescribeNetworkInterfacesOutput, error) {
	// This launches two requests. One delayed D by some constant.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "describeWithHedge")
	defer span.End()

	/*
	 * We take this approach because we cannot rely entirely on retries. The number 2 comes from the fact that 500
	 * microseconds is the median latency we see in prod, and ~1ish second is the 99%.
	 *
	 * Because the AWS client doesn't retry until it knows a network call has failed, and the calls don't fail
	 * because the connection is still in progress, we have to hedge. It doesn't seem like the underlying connection
	 * timeout is respected, because in Golang, the default round tripper has a timeout of 30 seconds.
	 *
	 * So, instead of waiting to retry, we start a second (or third) connection instead. Because the AWS client
	 * uses HTTP/1.1, only one request can be on a connection at a time. This means, if the prior request
	 * is still in progress, then the new request will end up on a different TCP connection. This means
	 * that it will likely end up taking a different network path due to ECMP, and succeed where others
	 * have failed.
	 */
	delays := []time.Duration{0, 2 * time.Second, 15 * time.Second}

	describerOutputChan := make(chan *describerOutput, len(delays))

	// TODO (Sargun): Do not hard code these.
	for idx := range delays {
		go describer(ctx, ec2client, enis, describerOutputChan, delays[idx])
	}

	var val *describerOutput
	// TODO: Handle case where we've started a second hedge, and the first one comes back in error.
	select {
	case <-ctx.Done():
		err := ctx.Err()
		if err == context.DeadlineExceeded {
			span.SetStatus(trace.Status{
				Code: trace.StatusCodeDeadlineExceeded,
			})
		} else if err == context.Canceled {
			span.SetStatus(trace.Status{
				Code: trace.StatusCodeCancelled,
			})
		} else {
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeUnknown,
				Message: err.Error(),
			})
		}

		return nil, err
	case val = <-describerOutputChan:
		if val.err != nil {
			if st, ok := status.FromError(val.err); ok {
				span.SetStatus(trace.Status{
					Code:    int32(st.Code()),
					Message: st.Message(),
				})
			} else {
				span.SetStatus(trace.Status{
					Code:    trace.StatusCodeUnknown,
					Message: val.err.Error(),
				})
			}
		}
		return val.describeNetworkInterfacesOutput, val.err
	}
}

func runDescribe(ctx context.Context, session *session.Session, items []*batchENIDescriptionRequestResponse) {
	if len(items) == 0 {
		panic("Asked to run describe with 0 items")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "runDescribe")
	defer span.End()

	start := time.Now()
	eniSet := set.NewThreadUnsafeSet()
	enis := make([]*string, 0, len(items))
	for idx := range items {
		eni := items[idx]
		if eniSet.Contains(eni.networkInterfaceID) {
			continue
		}
		eniSet.Add(eni.networkInterfaceID)
		enis = append(enis, &eni.networkInterfaceID)
	}

	span.AddAttributes(trace.StringAttribute("enis", eniSet.String()))
	ec2client := ec2.New(session)
	describeNetworkInterfacesOutput, err := describeWithHedge(ctx, ec2client, enis)

	// TODO: Write error handling logic is one of the ENIs does not exist.
	if err != nil {
		for idx := range items {
			items[idx].err = err
		}
	} else {
		for idx := range items {
			items[idx].networkInterfaces = describeNetworkInterfacesOutput.NetworkInterfaces
		}
	}
	stats.Record(ctx, batchLatency.M(time.Since(start).Nanoseconds()))
}

func (b *BatchENIDescriber) loop(ctx context.Context, maxItems int) {
	for {
		b.innerLoop(ctx, maxItems)
	}
}
func (b *BatchENIDescriber) innerLoop(ctx context.Context, maxItems int) {
	ctx, span := trace.StartSpan(ctx, "batchENIDescriberInnerLoop")
	defer span.End()
	spanContext := span.SpanContext()

	items := make([]*batchENIDescriptionRequestResponse, 0, maxItems)
	cases := make([]reflect.SelectCase, 1, maxItems+1)
	var start time.Time

	cases[0] = reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(b.requests),
	}

	for len(items) < maxItems {
		index, value, recvOK := reflect.Select(cases)
		if !recvOK {
			panic(fmt.Sprintf("Got not recvOk, with index %d, value: %s", index, value.String()))
		}
		if start.IsZero() {
			start = time.Now()
		}
		if index != 0 {
			break
		}

		// This is a new describe request
		newBatchENIDescriptionRequestResponse := value.Interface().(*batchENIDescriptionRequestResponse)
		items = append(items, newBatchENIDescriptionRequestResponse)
		newBatchENIDescriptionRequestResponse.span.AddLink(trace.Link{
			TraceID: spanContext.TraceID,
			SpanID:  spanContext.SpanID,
			Type:    trace.LinkTypeChild,
			Attributes: map[string]interface{}{
				"eni": newBatchENIDescriptionRequestResponse.networkInterfaceID,
			},
		})
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(newBatchENIDescriptionRequestResponse.triggerChannel),
		})

	}

	stats.Record(ctx, batchWaitPeriod.M(time.Since(start).Nanoseconds()), batchSize.M(int64(len(items))))
	go b.finishInnerLoop(ctx, items)
}

func (b *BatchENIDescriber) finishInnerLoop(ctx context.Context, items []*batchENIDescriptionRequestResponse) {
	// TODO: Add semaphore for maximum number of inflight describes.
	for idx := range items {
		close(items[idx].triggeredChannel)
	}
	b.runDescribe(ctx, b.session, items)
	for idx := range items {
		close(items[idx].doneCh)
	}
}

func (b *BatchENIDescriber) DescribeNetworkInterfaces(ctx context.Context, networkInterfaceID string) (*ec2.NetworkInterface, error) {
	return b.DescribeNetworkInterfacesWithTimeout(ctx, networkInterfaceID, b.maxDeadline)
}

func (b *BatchENIDescriber) DescribeNetworkInterfacesWithTimeout(ctx context.Context, networkInterfaceID string, deadline time.Duration) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "describeNetworkInterfacesWithTimeout")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("deadline", deadline.String()), trace.StringAttribute("eni", networkInterfaceID))

	ch := make(chan struct{})
	timer := time.NewTimer(deadline)
	defer timer.Stop()

	request := &batchENIDescriptionRequestResponse{
		networkInterfaceID: networkInterfaceID,
		doneCh:             ch,
		triggerChannel:     timer.C,
		triggeredChannel:   make(chan struct{}),
		span:               span,
	}

	// This really should never block. If it does, something might be very wrong.
	select {
	case b.requests <- request:
	case <-ctx.Done():
		return nil, errors.Wrap(ctx.Err(), "Could not write request. This seems very wrong")
	}

	// Once the request has been written, we wait for the executing channel to close, indicating that the request has begun processing
	// otherwise, we don't really start this span
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-request.triggeredChannel:
	}

	ctx, span = trace.StartSpan(ctx, "describeNetworkInterfacesWithTimeoutExecuting")
	defer span.End()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-request.doneCh:
	}

	if request.err != nil {
		err := HandleEC2Error(request.err, span)
		return nil, err
	}

	for idx := range request.networkInterfaces {
		if aws.StringValue(request.networkInterfaces[idx].NetworkInterfaceId) == networkInterfaceID {
			return request.networkInterfaces[idx], nil
		}
	}

	return nil, fmt.Errorf("Fatal, unknown error, interface id %s not found in response", networkInterfaceID)
}
