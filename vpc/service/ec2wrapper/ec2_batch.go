package ec2wrapper

import (
	"context"
	"fmt"
	"time"

	"go.opencensus.io/trace"

	"go.opencensus.io/stats"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
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

	// How long to wait for
	deadline time.Duration
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

func runDescribe(ctx context.Context, session *session.Session, items []*batchENIDescriptionRequestResponse) {
	if len(items) == 0 {
		panic("Asked to run describe with 0 items")
	}
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
	describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: enis,
	})

	// TODO: Write error handling logic is one of the ENIs does not exist.
	if err != nil {
		err = handleEC2Error(err, span)
		for idx := range items {
			items[idx].err = err
		}
	} else {
		for idx := range items {
			items[idx].networkInterfaces = describeNetworkInterfacesOutput.NetworkInterfaces
		}
	}
	stats.Record(ctx, batchLatency.M(time.Since(start).Nanoseconds()))
	for idx := range items {
		close(items[idx].doneCh)
	}
}

func (b *BatchENIDescriber) loop(ctx context.Context, maxItems int) {
	for {
		b.innerLoop(ctx, maxItems)
	}
}
func (b *BatchENIDescriber) innerLoop(ctx context.Context, maxItems int) {
	ctx, span := trace.StartSpan(ctx, "batchENIDescriberInnerLoop")
	defer span.End()

	items := make([]*batchENIDescriptionRequestResponse, 0, maxItems)
	nt := newTimer()
	defer nt.stop()
	var start time.Time

	for {
		select {
		case <-nt.c:
			goto runDescribe
		case item := <-b.requests:
			if start.IsZero() {
				start = time.Now()
			}
			nt.setDeadline(b.maxDeadline)
			items = append(items, item)
			if len(items) >= maxItems {
				goto runDescribe
			}

		}
	}
runDescribe:
	stats.Record(ctx, batchWaitPeriod.M(time.Since(start).Nanoseconds()), batchSize.M(int64(len(items))))
	go b.runDescribe(ctx, b.session, items)

}
func (b *BatchENIDescriber) DescribeNetworkInterfaces(ctx context.Context, networkInterfaceID string) (*ec2.NetworkInterface, error) {
	return b.DescribeNetworkInterfacesWithTimeout(ctx, networkInterfaceID, b.maxDeadline)
}

func (b *BatchENIDescriber) DescribeNetworkInterfacesWithTimeout(ctx context.Context, networkInterfaceID string, deadline time.Duration) (*ec2.NetworkInterface, error) {
	ch := make(chan struct{})
	request := &batchENIDescriptionRequestResponse{
		networkInterfaceID: networkInterfaceID,
		doneCh:             ch,
		deadline:           deadline,
	}

	b.requests <- request

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ch:
	}

	if request.err != nil {
		return nil, request.err
	}

	for idx := range request.networkInterfaces {
		if aws.StringValue(request.networkInterfaces[idx].NetworkInterfaceId) == networkInterfaceID {
			return request.networkInterfaces[idx], nil
		}
	}

	return nil, fmt.Errorf("Fatal, unknown error, interface id %s not found in request", networkInterfaceID)
}
