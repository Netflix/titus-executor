package provider

import (
	"context"
	"errors"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

// runtimeMock implements the Runtime interface
type runtimeMock struct {
	ctx context.Context

	mu sync.Mutex

	statusChan chan runtimeTypes.StatusMessage

	prepareCallback func(context.Context) error
	cleanupCallback func(*runtimeTypes.Container) error
	killCallback    func(c *runtimeTypes.Container) error

	shutdownAfter time.Timer
}

func (r *runtimeMock) Prepare(ctx context.Context, c *runtimeTypes.Container, bindMounts []string, startTime time.Time) error {
	logrus.Info("runtimeMock.Prepare", c.TaskID)
	if r.prepareCallback != nil {
		return r.prepareCallback(ctx)
	}
	return nil
}

func (r *runtimeMock) Start(ctx context.Context, c *runtimeTypes.Container) (string, *runtimeTypes.Details, <-chan runtimeTypes.StatusMessage, error) {
	logrus.Info("runtimeMock.Start", c.TaskID)
	r.mu.Lock()
	defer r.mu.Unlock()
	details := &runtimeTypes.Details{
		IPAddresses: make(map[string]string),
		NetworkConfiguration: &runtimeTypes.NetworkConfigurationDetails{
			IsRoutableIP: true,
			IPAddress: "1.2.3.4",
			EniID: "Sargun's favourite ENI",
		},
	}

	status := runtimeTypes.StatusMessage{
		Status: runtimeTypes.StatusRunning,
		Msg:    "running",
	}

	if r.statusChan == nil {
		r.statusChan = make(chan runtimeTypes.StatusMessage, 10)
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
	select {
	case <-time.After(30 * time.Second):
	case <-r.ctx.Done():
		logrus.Info("runtimeMock.Kill canceled")

		return errors.New("runtimeMock.Kill canceled")
	}
	return nil
}

func (r *runtimeMock) Cleanup(c *runtimeTypes.Container) error {
 	logrus.Info("runtimeMock.Cleanup", c.TaskID)
	if r.cleanupCallback != nil {
		return r.cleanupCallback(c)
	}
	return nil
}

