package executor

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers/testdriver"
	titusruntime "github.com/Netflix/titus-executor/executor/runtime"
	"github.com/Netflix/titus-executor/uploader"
)

var (
	_ titusruntime.Runtime = (*runtimeMock)(nil)
)

func TestMain(m *testing.M) {
	config.Load(context.TODO(), "./mock/config.json")

	os.Exit(m.Run())
}

// runtimeMock implements the Runtime interface
type runtimeMock struct {
	t   *testing.T
	ctx context.Context

	// kill requests
	kills chan<- chan<- struct{}

	mu sync.Mutex
	// subscription for one call to StartTask gets reset after each call
	startCalled chan<- struct{}
}

// test the launchGuard, it has caused too many deadlocks.
func TestHoldsLaunchesUntilStopFinishes(t *testing.T) { // nolint: gocyclo
	var (
		taskID   = "Titus-123-worker-0-2"
		image    = "titusops/alpine"
		taskInfo = &titus.ContainerInfo{
			ImageName: &image,
		}
		running     = make(chan struct{})
		startCalled = make(chan struct{})
		kills       = make(chan chan<- struct{}, 1)
		sub         = make(chan subscription)
		r, e        = mocks(t, kills, sub)
	)
	defer e.Stop()

	sub <- subscription{taskID: taskID, notify: running}
	// one task is running
	if err := e.StartTask(taskID, taskInfo, 512, 1, 1024, []uint16{}); err != nil {
		t.Fatal(err)
	}

	// wait for it to be up
	select {
	case <-time.After(5 * time.Second):
		t.Fatalf("Task %s not RUNNING after 5s", taskID)
	case <-running: // OK
	}

	// a pending Kill hangs until we tell it to proceed
	go func() {
		if err := e.StopTask(taskID); err != nil {
			t.Error(err)
		}
	}()
	// wait for the Kill to begin
	var killReq chan<- struct{}
	select {
	case killReq = <-kills:
	case <-time.After(5 * time.Second):
		t.Fatal("The Kill operation has not started yet after 5s")
	}

	r.notifyStartCalled(startCalled) // subscribe
	go func() {
		if err := e.StartTask("A-New-Task", taskInfo, 512, 1, 1024, []uint16{}); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-startCalled:
		t.Fatal("Executor must wait until the pending kill finish before launching tasks")
	default: // OK, expected
	}

	close(killReq) // let the kill finish

	select {
	case <-startCalled: // OK, expected
	case <-time.After(5 * time.Second):
		t.Fatal("Executor did not launch pending task within 5s after all kills finished")
	}
}

// prevent regressions: the executor once deadlocked when multiple kills for the same taskID were sent
func TestDoNotDeadlockWhenReceivingMultipleKillsForATask(t *testing.T) { // nolint: gocyclo
	var (
		taskIDs = []string{
			"Titus-111-worker-0-2",
			"Titus-222-worker-0-2",
			"Titus-333-worker-0-2",
		}
		image    = "titusops/alpine"
		taskInfo = &titus.ContainerInfo{
			ImageName: &image,
		}
		startCalled = make(chan struct{})
		kills       = make(chan chan<- struct{}, len(taskIDs))
		sub         = make(chan subscription)
		r, e        = mocks(t, kills, sub)
	)
	defer e.Stop()

	// a few tasks are running
	var notifications []<-chan struct{}
	for _, id := range taskIDs {
		running := make(chan struct{})
		notifications = append(notifications, running)
		sub <- subscription{taskID: id, notify: running}
		if err := e.StartTask(id, taskInfo, 512, 1, 1024, []uint16{}); err != nil {
			t.Fatal(err)
		}
	}
	// wait for all to be RUNNING
	var wg sync.WaitGroup
	for _, n := range notifications {
		wg.Add(1)
		go func(notify <-chan struct{}) {
			defer wg.Done()
			<-notify
		}(n)
	}
	wg.Wait()

	// pending kills for all of them
	for _, i := range taskIDs {
		go func(id string) {
			// hangs until we tell it to proceed
			if er := e.StopTask(id); er != nil {
				t.Error(er)
			}
		}(i)
	}
	// duplicate kill request for one of them
	go func() {
		if err := e.StopTask(taskIDs[rand.Intn(3)]); err != nil {
			t.Error(err)
		}
	}()

	// wait for all kills to start
	timeout := time.After(5 * time.Second)
	killRequests := make([]chan<- struct{}, 0, len(taskIDs))
	for range taskIDs {
		select {
		case req := <-kills:
			killRequests = append(killRequests, req)
		case <-timeout:
			t.Fatal("All kill operations have not started yet after 5s")
		}
	}

	r.notifyStartCalled(startCalled) // subscribe
	go func() {
		if err := e.StartTask("Another-Titus-Task", taskInfo, 512, 1, 1024, []uint16{}); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-startCalled:
		t.Fatal("Executor must wait until all pending kills finish before launching tasks")
	default: // OK, expected
	}

	// let one kill finish
	one, killRequests := killRequests[0], killRequests[1:]
	close(one)

	runtime.Gosched() // yield and give a chance for races to happen :)
	select {
	case <-startCalled:
		t.Fatal("Executor must wait until all pending kills finish before launching tasks")
	default: // OK, expected
	}

	// let the rest of the kills finish
	for _, req := range killRequests {
		close(req)
	}

	// now the launch can proceed
	select {
	case <-startCalled: // OK, expected
	case <-time.After(5 * time.Second):
		t.Fatal("Executor did not launch pending task within 5s after all kills finished")
	}
}

func mocks(t *testing.T, killRequests chan<- chan<- struct{}, sub <-chan subscription) (*runtimeMock, *Executor) {
	r := &runtimeMock{
		t:           t,
		startCalled: make(chan<- struct{}),
		kills:       killRequests,
	}
	l := uploader.NewUploadersFromUploaderArray([]uploader.Uploader{&uploader.NoopUploader{}})
	e, err := WithRuntime(metrics.Discard, func(ctx context.Context) (titusruntime.Runtime, error) {
		r.ctx = ctx
		return r, nil
	}, l)
	if err != nil {
		t.Fatal(err)
	}
	go e.Start()

	var driver *testdriver.TitusTestDriver
	driver, err = testdriver.New(e)
	if err != nil {
		t.Fatal(err)
	}
	go drain(t, driver.StatusChannel, sub)
	return r, e
}

// subscription allows notifications for when tasks are RUNNING
type subscription struct {
	taskID string
	notify chan<- struct{}
}

// drain the status channel allow others to be notified when particular Tasks are RUNNING
func drain(t *testing.T, c chan testdriver.TaskStatus, sub <-chan subscription) {
	subscriptions := make(map[string][]chan<- struct{})
	for {
		select {
		case status, ok := <-c:
			if !ok {
				return // channel is closed, nothing more to read
			}
			t.Logf("Reported status: %+v", status)
			if status.Status != "TASK_RUNNING" {
				continue // only notify when RUNNING
			}
			notifyAll(subscriptions, status.TaskID)
		case s := <-sub:
			subscriptions[s.taskID] = append(subscriptions[s.taskID], s.notify)
		}
	}
}

// notifyAll and clear subscriptions for a particular taskID
func notifyAll(subscriptions map[string][]chan<- struct{}, taskID string) {
	list, ok := subscriptions[taskID]
	if !ok {
		return
	}
	for _, notify := range list {
		close(notify)
	}
	delete(subscriptions, taskID)
}

func (r *runtimeMock) Prepare(ctx context.Context, c *titusruntime.Container, bindMounts []string) error {
	r.t.Log("runtimeMock.Prepare", c.TaskID)
	return nil
}

func (r *runtimeMock) Start(ctx context.Context, c *titusruntime.Container) (string, error) {
	r.t.Log("runtimeMock.Start", c.TaskID)
	r.mu.Lock()
	defer r.mu.Unlock()
	close(r.startCalled)
	r.startCalled = make(chan<- struct{}) // reset subscription
	return "", nil
}

func (r *runtimeMock) notifyStartCalled(notify chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startCalled = notify
}

func (r *runtimeMock) Kill(c *titusruntime.Container) error {
	r.t.Log("runtimeMock.Kill", c.TaskID)
	// send a kill request and wait for a grant
	req := make(chan struct{}, 1)
	select {
	case r.kills <- req:
	case <-r.ctx.Done():
		return errors.New("runtimeMock.Kill canceled")
	}
	select {
	case <-req:
	case <-r.ctx.Done():
		return errors.New("runtimeMock.Kill canceled")
	}
	return nil
}

func (r *runtimeMock) Cleanup(c *titusruntime.Container) error {
	r.t.Log("runtimeMock.Cleanup", c.TaskID)
	return nil
}

func (r *runtimeMock) Details(c *titusruntime.Container) (*titusruntime.Details, error) {
	r.t.Log("runtimeMock.Details", c.TaskID)
	return &titusruntime.Details{
		IPAddresses: make(map[string]string),
		NetworkConfiguration: &titusruntime.NetworkConfigurationDetails{
			IsRoutableIP: false,
		},
	}, nil
}

func (r *runtimeMock) Status(c *titusruntime.Container) (titusruntime.Status, error) {
	r.t.Log("runtimeMock.Status", c.TaskID)
	// always running is fine for these tests
	return titusruntime.StatusRunning, nil
}
