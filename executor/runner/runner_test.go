package runner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"net/http/httptest"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/launchguard/client"
	"github.com/Netflix/titus-executor/launchguard/server"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	_ runtimeTypes.Runtime = (*runtimeMock)(nil)
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		taskID   = "Titus-123-worker-0-2"
		image    = "titusops/alpine"
		taskInfo = &titus.ContainerInfo{
			ImageName: &image,
		}
		kills1    = make(chan chan<- struct{}, 1)
		launched1 = make(chan struct{})
		_, e1     = mocks(ctx, t, kills1, launched1)

		kills2    = make(chan chan<- struct{}, 1)
		launched2 = make(chan struct{})
		_, e2     = mocks(ctx, t, kills2, launched2)
	)

	defer func() {
		<-e1.StoppedChan
		<-e2.StoppedChan

	}()
	// one task is running
	if err := e1.StartTask(taskID, taskInfo, 512, 1, 1024); err != nil {
		t.Fatal(err)
	}

	// wait for it to be up
	select {
	case <-time.After(5 * time.Second):
		t.Fatalf("Task %s not RUNNING after 5s", taskID)
	case <-launched1: // OK
	}

	// a pending Kill hangs until we tell it to proceed
	go e1.Kill()
	// wait for the Kill to begin
	var killReq chan<- struct{}

	select {
	case killReq = <-kills1:
	case <-time.After(5 * time.Second):
		t.Fatal("The Kill operation has not started yet after 5s")
	}

	go func() {
		if err := e2.StartTask("A-New-Task", taskInfo, 512, 1, 1024); err != nil {
			t.Error(err)
		}
	}()

	select {
	case <-launched2:
		t.Fatal("Executor must wait until the pending kill finish before launching tasks")
	default: // OK, expected
	}

	close(killReq) // let the kill finish
	select {
	case <-launched2: // OK, expected
	case <-time.After(5 * time.Second):
		t.Fatal("Executor did not launch pending task within 5s after all kills finished")
	}
	cancel()
}

func mocks(ctx context.Context, t *testing.T, killRequests chan<- chan<- struct{}, taskLaunched chan struct{}) (*runtimeMock, *Runner) {
	lgs := httptest.NewServer(server.NewLaunchGuardServer(metrics.Discard))

	r := &runtimeMock{
		t:           t,
		startCalled: make(chan<- struct{}),
		kills:       killRequests,
		ctx:         ctx,
	}
	l := uploader.NewUploadersFromUploaderArray([]uploader.Uploader{&uploader.NoopUploader{}})
	cfg := config.Config{
		StatusCheckFrequency: time.Second,
	}

	e, err := WithRuntime(ctx, metrics.Discard, func(ctx context.Context, _cfg config.Config) (runtimeTypes.Runtime, error) {
		return r, nil
	}, l, cfg)
	if err != nil {
		t.Fatal(err)
	}

	e.launchGuard, err = client.NewLaunchGuardClient(metrics.Discard, lgs.URL)
	require.NoError(t, err)

	go drain(t, e, taskLaunched)
	return r, e
}

// drain the status channel allow others to be notified when particular Tasks are RUNNING
func drain(t *testing.T, e *Runner, taskLaunched chan struct{}) {
	for status := range e.UpdatesChan {
		t.Logf("Reported status: %+v", status)
		if status.State.String() == "TASK_RUNNING" {
			close(taskLaunched)
		}
	}
	t.Log("Drain complete")
}

func (r *runtimeMock) Prepare(ctx context.Context, c *runtimeTypes.Container, bindMounts []string) error {
	r.t.Log("runtimeMock.Prepare", c.TaskID)
	return nil
}

func (r *runtimeMock) Start(ctx context.Context, c *runtimeTypes.Container) (string, *runtimeTypes.Details, error) {
	r.t.Log("runtimeMock.Start", c.TaskID)
	r.mu.Lock()
	defer r.mu.Unlock()
	close(r.startCalled)
	r.startCalled = make(chan<- struct{}) // reset subscription
	details := &runtimeTypes.Details{
		IPAddresses: make(map[string]string),
		NetworkConfiguration: &runtimeTypes.NetworkConfigurationDetails{
			IsRoutableIP: false,
		},
	}
	return "", details, nil
}

func (r *runtimeMock) Kill(c *runtimeTypes.Container) error {
	logrus.Infof("runtimeMock.Kill (%v): %s", r.ctx, c.TaskID)
	defer logrus.Info("runtimeMock.Killed: ", c.TaskID)
	// send a kill request and wait for a grant
	req := make(chan struct{}, 1)
	select {
	case r.kills <- req:
	case <-r.ctx.Done():
		logrus.Info("runtimeMock.Kill canceled")
		return errors.New("runtimeMock.Kill canceled")
	}
	select {
	case <-req:
	case <-r.ctx.Done():
		logrus.Info("runtimeMock.Kill canceled")

		return errors.New("runtimeMock.Kill canceled")
	}
	return nil
}

func (r *runtimeMock) Cleanup(c *runtimeTypes.Container) error {
	r.t.Log("runtimeMock.Cleanup", c.TaskID)
	return nil
}

func (r *runtimeMock) Status(c *runtimeTypes.Container) (runtimeTypes.Status, error) {
	r.t.Log("runtimeMock.Status", c.TaskID)
	// always running is fine for these tests
	return runtimeTypes.StatusRunning, nil
}
