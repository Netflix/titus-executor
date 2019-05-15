package main

import (
	"context"
	"flag"
	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/Netflix/titus-executor/vk/backend"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"sync"
	"time"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"

	"os"
)

var (
	statusfd int
	podFileName string
)

func init() {
	flag.IntVar(&statusfd, "status-fd", 1, "The file descriptor to write status messages to")
	flag.StringVar(&podFileName, "pod", "", "The location of the pod spec (json-ish)")
}

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))
	ctx = log.WithLogger(ctx, log.L)


	// TODO: Setup journald logging
	// We use this to write status updates to
	// they're just plain old JSON statuses
	// If unset, we use PID 1.
	statuses := os.NewFile(uintptr(statusfd), "")
	defer statuses.Close()

	podFile, err := os.Open(podFileName)
	if err != nil {
		panic(err)
	}
	pod, err := backend.PodFromFile(podFile)
	if err != nil {
		panic(err)
	}

	log.G(ctx).WithField("pod", pod).Debug("Got pod")

	runtime := func(ctx context.Context, cfg config.Config) (runtimeTypes.Runtime, error) {
		return &runtimeMock{
			ctx: ctx,
		}, nil
	}

	cfg, _ := config.NewConfig()

	mockRunner, err := runner.WithRuntime(ctx, metrics.Discard, runtime, &uploader.Uploaders{}, *cfg)

	err = backend.RunWithBackend(ctx, mockRunner, statuses, pod)
	if err != nil {
		log.G(ctx).WithError(err).Fatal("Could not run container")
	}
}


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
