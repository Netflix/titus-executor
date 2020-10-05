package runner

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	titusdriver "github.com/Netflix/titus-executor/executor/drivers"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ runtimeTypes.Runtime = (*runtimeMock)(nil)
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

const (
	image = "titusops/alpine"
)

// runtimeMock implements the Runtime interface
type runtimeMock struct {
	t   *testing.T
	ctx context.Context

	// kill requests
	kills chan<- chan<- struct{}

	mu sync.Mutex
	// subscription for one call to StartTask gets reset after each call
	startCalled chan<- struct{}

	statusChan chan runtimeTypes.StatusMessage

	prepareCallback func(context.Context) error
	cleanupCallback func(*runtimeTypes.Container) error
	killCallback    func(c *runtimeTypes.Container) error
}

func (r *runtimeMock) Prepare(ctx context.Context, c *runtimeTypes.Container, bindMounts []string, startTime time.Time) error {
	r.t.Log("runtimeMock.Prepare", c.TaskID)
	if r.prepareCallback != nil {
		return r.prepareCallback(ctx)
	}
	return nil
}

func (r *runtimeMock) Start(ctx context.Context, c *runtimeTypes.Container) (string, *runtimeTypes.Details, <-chan runtimeTypes.StatusMessage, error) {
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

	status := runtimeTypes.StatusMessage{
		Status: runtimeTypes.StatusRunning,
		Msg:    "running",
	}

	// We can do this because it's buffered.
	r.statusChan <- status
	return "", details, r.statusChan, nil
}

func (r *runtimeMock) Kill(c *runtimeTypes.Container) error {
	logrus.Infof("runtimeMock.Kill (%v): %s", r.ctx, c.TaskID)
	if r.killCallback != nil {
		return r.killCallback(c)
	}
	defer close(r.statusChan)
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
	if r.cleanupCallback != nil {
		return r.cleanupCallback(c)
	}
	return nil
}

func TestSendTerminalStatusUntilCleanup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskID := "TestSendTerminalStatusUntilCleanup"
	image := image
	taskInfo := &titus.ContainerInfo{
		ImageName:         &image,
		IgnoreLaunchGuard: proto.Bool(true),
	}
	kills := make(chan chan<- struct{}, 1)

	statusChan := make(chan runtimeTypes.StatusMessage, 10)
	r := &runtimeMock{
		t:           t,
		startCalled: make(chan<- struct{}),
		kills:       kills,
		ctx:         ctx,
		statusChan:  statusChan,
	}
	cleanedup := false
	killed := false
	r.killCallback = func(c *runtimeTypes.Container) error {
		logrus.WithField("container", c).Debug("Container being killed")
		killed = true
		return nil
	}
	r.cleanupCallback = func(c *runtimeTypes.Container) error {
		assert.True(t, killed) // Make sure the service is killed before cleand up
		logrus.WithField("container", c).Debug("Container being cleaned up")
		cleanedup = true
		return nil
	}

	executor, err := WithRuntime(ctx, metrics.Discard, func(ctx context.Context, _cfg config.Config) (runtimeTypes.Runtime, error) {
		return r, nil
	}, config.Config{})

	require.NoError(t, err)
	require.NoError(t, executor.StartTask(taskID, taskInfo, 1, 1, 0, 1, 1))

	defer time.Sleep(1 * time.Second)
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case update, ok := <-executor.UpdatesChan:
			if !ok {
				t.Fatal("Updates Chan Closed")
				return
			}
			logrus.Debug("Got update: ", update)
			switch update.State {
			case titusdriver.Running:
				logrus.Debug("Task Running, marking finished")
				r.statusChan <- runtimeTypes.StatusMessage{
					Status: runtimeTypes.StatusFinished,
					Msg:    "running",
				}
				logrus.Debug("Task Running, marked finished")
			case titusdriver.Finished:
				logrus.Debug("Received finished, marked finished")
				goto out
			}
		case <-timeout.C:
			t.Fatal("Test timed out")
		case <-ctx.Done():
			t.Fatal("Context complete?")
		}
	}

out:
	assert.True(t, cleanedup)
	assert.True(t, killed)

}

func TestCancelDuringPrepare(t *testing.T) { // nolint: gocyclo
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskID := "TestCancelDuringPrepare"
	image := image
	taskInfo := &titus.ContainerInfo{
		ImageName:         &image,
		IgnoreLaunchGuard: proto.Bool(true),
	}
	kills := make(chan chan<- struct{}, 1)

	statusChan := make(chan runtimeTypes.StatusMessage, 10)
	r := &runtimeMock{
		t:           t,
		startCalled: make(chan<- struct{}),
		kills:       kills,
		ctx:         ctx,
		statusChan:  statusChan,
	}

	r.prepareCallback = func(c context.Context) error {
		<-c.Done()
		return c.Err()
	}

	executor, err := WithRuntime(ctx, metrics.Discard, func(ctx context.Context, _cfg config.Config) (runtimeTypes.Runtime, error) {
		return r, nil
	}, config.Config{})

	require.NoError(t, err)
	require.NoError(t, executor.StartTask(taskID, taskInfo, 1, 1, 0, 1, 1))

	testFailed := make(chan struct{})
	time.AfterFunc(30*time.Second, func() {
		close(testFailed)
	})
	defer time.Sleep(1 * time.Second)

	for {
		select {
		case update, ok := <-executor.UpdatesChan:
			if !ok {
				t.Fatal("Updates Chan Closed")
				return
			}
			logrus.Debug("Got update: ", update)
			switch update.State {
			case titusdriver.Starting:
				logrus.Debug("Killing task, now that it's entered starting")
				executor.Kill()
				logrus.Debug("Killed task, now that it's entered starting")
			case titusdriver.Killed:
				return
			default:
				t.Fatal("Unknown state: ", update)
			}
		case kill := <-kills:
			close(kill)
			goto phase2
		case <-testFailed:
			panic("Test Failed, executor didn't yield when killed in prepare")
		case <-ctx.Done():
			t.Fatal("Context complete?")
		}
	}

phase2:
	for {
		select {
		case update := <-executor.UpdatesChan:
			logrus.Debug("Got update: ", update)
			switch update.State {
			case titusdriver.Killed:
				return
			default:
				t.Fatal("Received state other than killed: ", update)
			}
		case <-kills:
			t.Fatal("Received another kill")
		case <-testFailed:
			panic("Test Failed, executor passed kill to runtime, but did not yield")
		case <-ctx.Done():
			t.Fatal("Context complete?")
		}
	}
}

func TestSendRedundantStatusMessage(t *testing.T) { // nolint: gocyclo
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskID := "Titus-123-worker-0-2"
	image := image
	taskInfo := &titus.ContainerInfo{
		ImageName:         &image,
		IgnoreLaunchGuard: proto.Bool(true),
	}
	kills := make(chan chan<- struct{}, 1)

	statusChan := make(chan runtimeTypes.StatusMessage, 10)
	r := &runtimeMock{
		t:           t,
		startCalled: make(chan<- struct{}),
		kills:       kills,
		ctx:         ctx,
		statusChan:  statusChan,
	}

	executor, err := WithRuntime(ctx, metrics.Discard, func(ctx context.Context, _cfg config.Config) (runtimeTypes.Runtime, error) {
		return r, nil
	}, config.Config{})

	require.NoError(t, err)
	require.NoError(t, executor.StartTask(taskID, taskInfo, 1, 1, 0, 1, 1))

	killTimeout := time.NewTimer(15 * time.Second)
	defer killTimeout.Stop()

	var lastUpdate Update
	for {
		select {
		case update := <-executor.UpdatesChan:
			lastUpdate = update
			if update.State == titusdriver.Running {
				goto running
			}
		case <-killTimeout.C:
			t.Fatal("Kill timeout received")
		}
	}
running:
	// We'll kill the task after a few seconds
	time.AfterFunc(5*time.Second, func() {
		// This should be idempotent
		t.Log("Killing task")
		executor.Kill()
		executor.Kill()
		executor.Kill()
	})

	// Ensure we're in a "good" state
	assert.Equal(t, lastUpdate.State, titusdriver.Running)
	assert.Equal(t, lastUpdate.Mesg, "running")

	go func() {
		statusChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    "running",
		}
		statusChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    "running",
		}
		statusChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    "running2",
		}
		statusChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    "running2",
		}
		statusChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    "running2",
		}
		statusChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    "running3",
		}
	}()

	for {
		select {
		case update := <-executor.UpdatesChan:
			assert.Equal(t, update.State, titusdriver.Running)
			assert.Equal(t, update.Mesg, "running2")
			goto running2
		case <-killTimeout.C:
			t.Fatal("Kill timeout received")
		}
	}

running2:
	for {
		select {
		case update := <-executor.UpdatesChan:
			assert.Equal(t, update.State, titusdriver.Running)
			assert.Equal(t, update.Mesg, "running3")
			goto done
		case <-killTimeout.C:
			t.Fatal("Kill timeout received")
		}
	}
done:

	// This will release the kill
	go func() {
		kill := <-kills
		close(kill)
	}()
	executor.Kill()
	select {
	case update := <-executor.UpdatesChan:
		assert.Equal(t, update.State, titusdriver.Killed)
	case <-killTimeout.C:
		t.Fatal("Kill timeout received")
	}
}
