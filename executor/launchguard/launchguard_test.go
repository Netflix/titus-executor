package launchguard

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
)

func TestNoopEvent(t *testing.T) {
	event := NoopCleanUpEvent{}
	event.Done()
}

func TestContext(t *testing.T) {
	timer := time.AfterFunc(10*time.Second, func() {
		t.Fatal("Event timed out")
	})
	defer timer.Stop()

	lg := NewLaunchGuard(metrics.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	NewRealCleanUpEvent(ctx, lg)
	le1 := NewLaunchEvent(lg)

	select {
	case <-le1.Launch():
		t.Fatal("Unknown state")
	default:
	}
	cancel()
	<-le1.Launch()
}
func TestBasicOrdering(t *testing.T) {
	timer := time.AfterFunc(10*time.Second, func() {
		t.Fatal("Event timed out")
	})
	defer timer.Stop()

	lg := NewLaunchGuard(metrics.Discard)
	ce1 := NewRealCleanUpEvent(context.TODO(), lg)
	le1 := NewLaunchEvent(lg)
	le2 := NewLaunchEvent(lg)
	ce2 := NewRealCleanUpEvent(context.TODO(), lg)
	ce3 := NewRealCleanUpEvent(context.TODO(), lg)
	le3 := NewLaunchEvent(lg)
	le4 := NewLaunchEvent(lg)
	ce5 := NewRealCleanUpEvent(context.TODO(), lg)
	le5 := NewLaunchEvent(lg)
	ce6 := NewRealCleanUpEvent(context.TODO(), lg)
	ce7 := NewRealCleanUpEvent(context.TODO(), lg)
	ce8 := NewRealCleanUpEvent(context.TODO(), lg)
	ce9 := NewRealCleanUpEvent(context.TODO(), lg)

	ce1.Done()
	<-le1.Launch()
	<-le2.Launch()
	ce2.Done()
	ce3.Done()
	<-le3.Launch()
	<-le4.Launch()
	ce5.Done()
	<-le5.Launch()
	ce6.Done()
	ce7.Done()
	ce8.Done()
	ce9.Done()
}

func TestEmptyLaunchGuard(t *testing.T) {
	lg := NewLaunchGuard(metrics.Discard)
	le := NewLaunchEvent(lg)
	<-le.Launch()
	<-le.Launch()
	<-le.Launch()

}

var (
	_ LaunchEvent = (*testLaunchEvent)(nil)
)

type testLaunchEvent struct {
	sharedCounter *int32
	intendedIdx   int32
	t             *testing.T
	wg            *sync.WaitGroup
}

func (le *testLaunchEvent) notifyLaunch() {
	defer le.wg.Done()
	oldValue := atomic.AddInt32(le.sharedCounter, 1) - 1
	if oldValue != le.intendedIdx {
		le.t.Fatalf("Unlock idx: %d, startIdx: %d", oldValue, le.intendedIdx)
	}
}

func (le *testLaunchEvent) Launch() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

func TestLaunchGuard(t *testing.T) {
	timer := time.AfterFunc(10*time.Second, func() {
		t.Fatal("Event timed out")
	})
	defer timer.Stop()

	var sharedCounter int32
	wg := &sync.WaitGroup{}
	numCases := rand.Intn(100000)
	t.Log("Number of test cases: ", numCases)
	lg := NewLaunchGuard(metrics.Discard)

	var launchIdx int32
	cleanupTestCases := []CleanUpEvent{}

	for i := 0; i < numCases; i++ {
		if rand.Intn(2) == 0 {
			wg.Add(1)
			le := &testLaunchEvent{
				wg:            wg,
				sharedCounter: &sharedCounter,
				intendedIdx:   launchIdx,
				t:             t,
			}
			lg.launchEventChan <- le
			launchIdx++
		} else {
			cleanupTestCases = append(cleanupTestCases, NewRealCleanUpEvent(context.TODO(), lg))
		}
	}

	// Let's call each cleanup event twice for fun
	testCleanupIdxs := append(rand.Perm(len(cleanupTestCases)), rand.Perm(len(cleanupTestCases))...)

	for _, idx := range testCleanupIdxs {
		cleanupTestCases[idx].Done()
	}

	wg.Wait()
}
