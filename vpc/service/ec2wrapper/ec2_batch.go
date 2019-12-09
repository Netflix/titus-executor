package ec2wrapper

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/session"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	batchWaitPeriod = stats.Int64("getInterface.waitTimeNs", "How long calls on get interface waited", "ns")
	batchSize       = stats.Int64("getInterface.size", "How many interfaces are normally called at once", "")
	batchLatency    = stats.Int64("getInterface.latencyNs", "How many interfaces are normally called at once", "ns")
)

type batchRequestResponse struct {
	span *trace.Span
	name string
	// triggeredChannel is closed when we accept / begin executing on this request
	// it is expected to be set by the user
	triggeredChannel chan struct{}
	// timer is a drop-dead timer for when this should start executing
	timer *time.Timer
	// It is closed when the fields below have been populated
	doneCh chan struct{}
	// Fields populated once the reply is done
	err      error
	response interface{}
}

type BatchDescriber struct {
	session     *session.Session
	requests    chan *batchRequestResponse
	maxDeadline time.Duration

	runDescribe func(ctx context.Context, session *session.Session, items []*batchRequestResponse)
}

type BatchENIDescriber struct {
	BatchDescriber
}

// TODO: This currently leaks goroutines.
func NewBatchENIDescriber(ctx context.Context, maxDeadline time.Duration, maxItems int, session *session.Session) *BatchENIDescriber {
	describer := &BatchENIDescriber{
		BatchDescriber{
			session:     session,
			requests:    make(chan *batchRequestResponse, maxItems*10),
			runDescribe: runDescribeENIs,
			maxDeadline: maxDeadline,
		},
	}

	go describer.loop(ctx, maxItems)

	return describer
}

func runDescribeENIs(ctx context.Context, session *session.Session, items []*batchRequestResponse) { // nolint:dupl
	if len(items) == 0 {
		panic("Asked to run describe with 0 items")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "runDescribeENIs")
	defer span.End()

	start := time.Now()
	eniSet := sets.NewString()
	enis := make([]*string, 0, len(items))
	for idx := range items {
		eni := items[idx]
		if eniSet.Has(eni.name) {
			continue
		}
		eniSet.Insert(eni.name)
		enis = append(enis, &eni.name)
	}

	span.AddAttributes(trace.StringAttribute("enis", fmt.Sprint(eniSet.List())))
	ec2client := ec2.New(session)
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
	req := func(ctx2 context.Context) (interface{}, error) {
		return ec2client.DescribeNetworkInterfacesWithContext(ctx2, &ec2.DescribeNetworkInterfacesInput{
			NetworkInterfaceIds: enis,
		})
	}
	describeNetworkInterfacesOutput, err := hedge(ctx, req, delays)

	// TODO: Write error handling logic is one of the ENIs does not exist.
	if err != nil {
		for idx := range items {
			items[idx].err = err
		}
	} else {
		for idx := range items {
			items[idx].response = describeNetworkInterfacesOutput
		}
	}
	stats.Record(ctx, batchLatency.M(time.Since(start).Nanoseconds()))
}

func (b *BatchDescriber) loop(ctx context.Context, maxItems int) {
	for {
		b.innerLoop(ctx, maxItems)
	}
}
func (b *BatchDescriber) innerLoop(ctx context.Context, maxItems int) {
	ctx, span := trace.StartSpan(ctx, "innerLoop")
	defer span.End()
	spanContext := span.SpanContext()

	doneCh := make(chan struct{})
	items := make([]*batchRequestResponse, 0, maxItems)
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
		newBatchENIDescriptionRequestResponse := value.Interface().(*batchRequestResponse)
		items = append(items, newBatchENIDescriptionRequestResponse)
		newBatchENIDescriptionRequestResponse.span.AddLink(trace.Link{
			TraceID: spanContext.TraceID,
			SpanID:  spanContext.SpanID,
			Type:    trace.LinkTypeChild,
			Attributes: map[string]interface{}{
				"name": newBatchENIDescriptionRequestResponse.name,
			},
		})
		newBatchENIDescriptionRequestResponse.doneCh = doneCh
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(newBatchENIDescriptionRequestResponse.timer.C),
		})

	}

	stats.Record(ctx, batchWaitPeriod.M(time.Since(start).Nanoseconds()), batchSize.M(int64(len(items))))
	go b.finishInnerLoop(ctx, items, doneCh)
}

func (b *BatchDescriber) finishInnerLoop(ctx context.Context, items []*batchRequestResponse, doneCh chan struct{}) {
	// TODO: Add semaphore for maximum number of inflight describes.
	defer close(doneCh)
	for idx := range items {
		close(items[idx].triggeredChannel)
	}
	b.runDescribe(ctx, b.session, items)
}

func (b *BatchENIDescriber) DescribeNetworkInterfaces(ctx context.Context, networkInterfaceID string) (*ec2.NetworkInterface, error) {
	return b.DescribeNetworkInterfacesWithTimeout(ctx, networkInterfaceID, b.maxDeadline)
}

func (b *BatchENIDescriber) DescribeNetworkInterfacesWithTimeout(ctx context.Context, networkInterfaceID string, deadline time.Duration) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "describeNetworkInterfacesWithTimeout")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("deadline", deadline.String()), trace.StringAttribute("eni", networkInterfaceID))

	timer := time.NewTimer(deadline)
	defer timer.Stop()

	request := &batchRequestResponse{
		name:             networkInterfaceID,
		timer:            timer,
		triggeredChannel: make(chan struct{}),
		span:             span,
	}

	// This really should never block. If it does, something might be very wrong.
	select {
	case b.requests <- request:
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, errors.Wrap(ctx.Err(), "Could not write request before deadline exceeded. This seems very wrong")
		}
		return nil, ctx.Err()
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

	for _, iface := range request.response.(*ec2.DescribeNetworkInterfacesOutput).NetworkInterfaces {
		if aws.StringValue(iface.NetworkInterfaceId) == networkInterfaceID {
			ret := iface
			return ret, nil
		}
	}

	return nil, fmt.Errorf("Fatal, unknown error, interface id %s not found in response", networkInterfaceID)
}

type BatchInstanceDescriber struct {
	BatchDescriber
}

func runDescribeInstances(ctx context.Context, session *session.Session, items []*batchRequestResponse) { // nolint:dupl
	if len(items) == 0 {
		panic("Asked to run describe with 0 items")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "runDescribeInstances")
	defer span.End()

	start := time.Now()
	instancesSet := sets.NewString()
	instances := make([]*string, 0, len(items))
	for idx := range items {
		eni := items[idx]
		if instancesSet.Has(eni.name) {
			continue
		}
		instancesSet.Insert(eni.name)
		instances = append(instances, &eni.name)
	}

	span.AddAttributes(trace.StringAttribute("instances", fmt.Sprint(instancesSet.List())))
	ec2client := ec2.New(session)
	delays := []time.Duration{0, 2 * time.Second, 15 * time.Second}
	req := func(ctx2 context.Context) (interface{}, error) {
		return ec2client.DescribeInstancesWithContext(ctx2, &ec2.DescribeInstancesInput{
			InstanceIds: instances,
		})
	}
	describeNetworkInterfacesOutput, err := hedge(ctx, req, delays)

	// TODO: Write error handling logic is one of the ENIs does not exist.
	if err != nil {
		for idx := range items {
			items[idx].err = err
		}
	} else {
		for idx := range items {
			items[idx].response = describeNetworkInterfacesOutput
		}
	}
	stats.Record(ctx, batchLatency.M(time.Since(start).Nanoseconds()))
}

// TODO: This currently leaks goroutines.
func NewBatchInstanceDescriber(ctx context.Context, maxDeadline time.Duration, maxItems int, session *session.Session) *BatchInstanceDescriber {
	describer := &BatchInstanceDescriber{
		BatchDescriber{
			session:     session,
			requests:    make(chan *batchRequestResponse, maxItems*10),
			runDescribe: runDescribeInstances,
			maxDeadline: maxDeadline,
		},
	}

	go describer.loop(ctx, maxItems)

	return describer
}

func (b *BatchInstanceDescriber) DescribeInstanceWithTimeout(ctx context.Context, instanceID string, deadline time.Duration) (*ec2.Reservation, error) {
	ctx, span := trace.StartSpan(ctx, "describeInstanceWithTimeout")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("deadline", deadline.String()), trace.StringAttribute("instanceID", instanceID))

	timer := time.NewTimer(deadline)
	defer timer.Stop()

	request := &batchRequestResponse{
		name:             instanceID,
		timer:            timer,
		triggeredChannel: make(chan struct{}),
		span:             span,
	}

	// This really should never block. If it does, something might be very wrong.
	select {
	case b.requests <- request:
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return nil, errors.Wrap(ctx.Err(), "Could not write request before deadline exceeded. This seems very wrong")
		}
		return nil, ctx.Err()
	}

	// Once the request has been written, we wait for the executing channel to close, indicating that the request has begun processing
	// otherwise, we don't really start this span
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-request.triggeredChannel:
	}

	ctx, span = trace.StartSpan(ctx, "describeInstanceWithTimeoutExecuting")
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

	for _, resv := range request.response.(*ec2.DescribeInstancesOutput).Reservations {
		if len(resv.Instances) != 1 {
			return nil, fmt.Errorf("Reservation contains weird number of instances (%d)", len(resv.Instances))
		}
		for _, instance := range resv.Instances {
			if aws.StringValue(instance.InstanceId) == instanceID {
				ret := resv
				return ret, nil
			}
		}
	}

	return nil, fmt.Errorf("Fatal, unknown error, interface id %s not found in response", instanceID)
}
