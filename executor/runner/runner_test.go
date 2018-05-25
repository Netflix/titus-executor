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
	"github.com/Netflix/titus-executor/executor/drivers"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/uploader"
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
}

func (r *runtimeMock) Prepare(ctx context.Context, c *runtimeTypes.Container, bindMounts []string) error {
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
	return nil
}

func TestCancelDuringPrepare(t *testing.T) { // nolint: gocyclo
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskID := "TestCancelDuringPrepare"
	image := "titusops/alpine"
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

	l := uploader.NewUploadersFromUploaderArray([]uploader.Uploader{&uploader.NoopUploader{}})
	cfg := config.Config{}

	executor, err := WithRuntime(ctx, metrics.Discard, func(ctx context.Context, _cfg config.Config) (runtimeTypes.Runtime, error) {
		return r, nil
	}, l, cfg)
	require.NoError(t, err)
	require.NoError(t, executor.StartTask(taskID, taskInfo, 1, 1, 1))

	once := sync.Once{}

	testFailed := make(chan struct{})
	time.AfterFunc(30*time.Second, func() {
		close(testFailed)
	})

	for {
		select {
		case update := <-executor.UpdatesChan:
			logrus.Debug("Got update: ", update)
			switch update.State {
			case titusdriver.Starting:
				once.Do(func() {
					executor.Kill()
					logrus.Debug("Killing task, now that it's entered starting")
				})
			case titusdriver.Lost:
				return
			default:
				t.Fatal("Unknown state: ", update)
			}
		case <-testFailed:
			panic("Test Failed, executor didn't yield when killed in prepare")
		case <-ctx.Done():
			t.Fatal("Context complete?")
		}
	}
}

func TestSendRedundantStatusMessage(t *testing.T) { // nolint: gocyclo
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	taskID := "Titus-123-worker-0-2"
	image := "titusops/alpine"
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

	l := uploader.NewUploadersFromUploaderArray([]uploader.Uploader{&uploader.NoopUploader{}})
	cfg := config.Config{}

	executor, err := WithRuntime(ctx, metrics.Discard, func(ctx context.Context, _cfg config.Config) (runtimeTypes.Runtime, error) {
		return r, nil
	}, l, cfg)
	require.NoError(t, err)
	require.NoError(t, executor.StartTask(taskID, taskInfo, 1, 1, 1))

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
