package ec2wrapper

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/session"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"golang.org/x/sync/errgroup"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestEC2BatchTest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	var describes int64
	bed := NewBatchENIDescriber(ctx, 100*time.Millisecond, 3, nil)
	bed.runDescribe = func(ctx context.Context, session *session.Session, items []*batchENIDescriptionRequestResponse) {
		atomic.AddInt64(&describes, 1)
		t.Log("Described: ", items)
		result := make([]*ec2.NetworkInterface, len(items))
		for itemIdx := range items {
			result[itemIdx] = &ec2.NetworkInterface{
				NetworkInterfaceId: aws.String(items[itemIdx].networkInterfaceID),
			}
		}
		for itemIdx := range items {
			items[itemIdx].networkInterfaces = result
		}
	}

	group, errGroupCtx := errgroup.WithContext(ctx)
	call := func() error {
		_, err := bed.DescribeNetworkInterfaces(errGroupCtx, fmt.Sprintf("foo-%d", rand.Int())) // nolint: gosec
		return err
	}

	group.Go(call)
	group.Go(call)
	group.Go(call)
	// We hit the three limit above, so it triggered
	group.Go(call)
	group.Go(call)
	group.Go(call)
	// We hit the three limit above so it triggered
	group.Go(call)
	group.Go(call)
	time.Sleep(500 * time.Millisecond)
	// We hit the 100 millisecond tick, so it triggered

	actualDescribes := atomic.LoadInt64(&describes)
	assert.NilError(t, group.Wait())
	assert.Assert(t, is.DeepEqual(int(actualDescribes), 3))
}
