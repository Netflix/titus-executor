package ec2wrapper

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"gotest.tools/assert"
)

func TestEC2BatchTest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var describes int64
	bed := NewBatchENIDescriber(ctx, 100*time.Millisecond, 3, nil)
	bed.runDescribe = func(ctx context.Context, session *session.Session, items []*batchENIDescriptionRequestResponse) {
		atomic.AddInt64(&describes, 1)
	}
	call := func() {
		_, _ = bed.DescribeNetworkInterfaces(ctx, "foo")
	}

	go call()
	go call()
	go call()
	// We hit the three limit above, so it triggered
	go call()
	go call()
	go call()
	// We hit the three limit above so it triggered
	go call()
	go call()
	time.Sleep(500 * time.Millisecond)
	// We hit the 100 millisecond tick, so it triggered

	assert.Assert(t, atomic.LoadInt64(&describes) == 3)
}
