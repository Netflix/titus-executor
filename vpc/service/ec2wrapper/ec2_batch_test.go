package ec2wrapper

import (
	"context"
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/sync/errgroup"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestEC2BatchTest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	var describes int64
	bed := NewBatchENIDescriber(ctx, 100*time.Millisecond, 3, nil)
	bed.runDescribe = func(ctx context.Context, session *session.Session, items []*batchRequestResponse) {
		atomic.AddInt64(&describes, 1)
		t.Log("Described: ", items)
		result := make([]*ec2.NetworkInterface, len(items))
		for itemIdx := range items {
			result[itemIdx] = &ec2.NetworkInterface{
				NetworkInterfaceId: aws.String(items[itemIdx].name),
			}
		}
		for itemIdx := range items {
			items[itemIdx].response = &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: result,
				NextToken:         nil,
			}
		}
	}

	group, errGroupCtx := errgroup.WithContext(ctx)
	call := func() error {
		id := fmt.Sprintf("foo-%d", rand.Int()) // nolint: gosec
		resp, err := bed.DescribeNetworkInterfaces(errGroupCtx, id)
		if nid := aws.StringValue(resp.NetworkInterfaceId); nid != id {
			return fmt.Errorf("Returned network interface ID: %s doesn't match passed in id %s", nid, id)
		}
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
