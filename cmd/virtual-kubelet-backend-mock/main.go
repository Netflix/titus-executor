package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	executorTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/vk/backend"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"gopkg.in/urfave/cli.v1"
)

func main() {
	var podFileName string
	var statusPipe string

	var flags = []cli.Flag{
		cli.StringFlag{
			Name:        "pod",
			Destination: &podFileName,
			Usage:       "The location of the pod spec file (json-ish)",
		},
		cli.StringFlag{
			Name:        "status",
			Destination: &statusPipe,
			Usage:       "The location of the status pipe",
		},
	}

	app := cli.NewApp()
	app.Name = "virtual-kubelet-backend-mock"
	// avoid os.Exit as much as possible to let deferred functions run
	defer time.Sleep(1 * time.Second)

	app.Flags = flags
	app.Action = func(c *cli.Context) error {
		if err := mainWithError(podFileName, statusPipe); err != nil {
			return cli.NewExitError(err, 1)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func mainWithError(podFileName string, statusPipe string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))
	ctx = log.WithLogger(ctx, log.L)

	podFile, err := os.Open(podFileName)
	if err != nil {
		panic(err)
	}

	pod, err := backend.PodFromFile(podFile)
	if err != nil {
		panic(err)
	}
	log.G(ctx).WithField("pod", pod).Debug("Got pod")

	pipe, err := os.OpenFile(statusPipe, os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	defer pipe.Close()
	log.G(ctx).WithField("pod", pod.Name).Debugf("Got pipe %v", statusPipe)

	runtime := func(ctx context.Context, c executorTypes.Container, startTime time.Time) (executorTypes.Runtime, error) {
		rm := &runtimeMock{}

		var timer *time.Timer
		behavior := NewRunStateBehavior(pod)
		delayWithJitter := behavior.DelayWithJitter()
		log.G(ctx).WithField("behavior", behavior).WithField("delayWithJitter", delayWithJitter).Info("Run state behavior")
		if delayWithJitter > 0 {
			timer = time.AfterFunc(delayWithJitter, func() {
				rm.statusChan <- runtimeTypes.StatusMessage{
					Status: behavior.ExecutionStatus,
					Msg:    behavior.Message,
				}
			})
		}

		rm.ctx = ctx
		rm.prepareCallback = func(ctx2 context.Context) error {
			behavior := NewPrepareStateBehavior(pod)
			delayWithJitter := behavior.DelayWithJitter()
			log.G(ctx).WithField("behavior", behavior).WithField("delayWithJitter", delayWithJitter).Info("Prepared state behavior")
			if delayWithJitter > 0 {
				time.Sleep(delayWithJitter)
			}
			return nil
		}
		rm.killCallback = func(ctx2 context.Context) error {
			if timer != nil {
				timer.Stop()
			}
			behavior := NewKillStateBehavior(pod)
			delayWithJitter := behavior.DelayWithJitter()
			log.G(ctx).WithField("behavior", behavior).WithField("delayWithJitter", delayWithJitter).Info("Kill state behavior")
			if delayWithJitter > 0 {
				time.Sleep(delayWithJitter)
			}
			return nil
		}
		return rm, nil
	}

	cfg, _ := config.NewConfig()

	b, err := backend.NewBackend(ctx, runtime, pod, cfg, metrics.Discard)
	if err != nil {
		return fmt.Errorf("Could not instantiate backend: %w", err)
	}

	err = b.RunWithStatusFile(ctx, pipe)
	if err != nil {
		return fmt.Errorf("Could not start container: %w", err)
	}

	if err != nil {
		log.G(ctx).WithError(err).Fatal("Could not run container")
	}

	return err
}

// runtimeMock implements the Runtime interface
type runtimeMock struct {
	ctx context.Context

	mu     sync.Mutex
	taskId string

	statusChan chan runtimeTypes.StatusMessage

	prepareCallback func(context.Context) error
	cleanupCallback func(context.Context) error
	killCallback    func(context.Context) error

	shutdownAfter time.Timer
}

func (r *runtimeMock) Prepare(containerCtx context.Context) error {
	logrus.Info("runtimeMock.Prepare", r.taskId)
	if r.prepareCallback != nil {
		return r.prepareCallback(containerCtx)
	}
	return nil
}

func (r *runtimeMock) Start(containerCtx context.Context) (string, *runtimeTypes.Details, <-chan runtimeTypes.StatusMessage, error) {
	logrus.Info("runtimeMock.Start", r.taskId)
	r.mu.Lock()
	defer r.mu.Unlock()
	details := &runtimeTypes.Details{
		IPAddresses: make(map[string]string),
		NetworkConfiguration: &runtimeTypes.NetworkConfigurationDetails{
			IsRoutableIP: true,
			IPAddress:    "1.2.3.4",
			EniID:        "Sargun's favourite ENI",
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

func (r *runtimeMock) Kill(ctx context.Context) error {
	logrus.Infof("runtimeMock.Kill (%v): %s", r.ctx, r.taskId)
	if r.killCallback != nil {
		return r.killCallback(ctx)
	}
	defer close(r.statusChan)
	defer logrus.Info("runtimeMock.Killed: ", r.taskId)
	// send a kill request and wait for a grant
	select {
	case <-r.ctx.Done():
		logrus.Info("runtimeMock.Kill canceled")

		return errors.New("runtimeMock.Kill canceled")
	}
	return nil
}

func (r *runtimeMock) Cleanup(ctx context.Context) error {
	logrus.Info("runtimeMock.Cleanup", r.taskId)
	if r.cleanupCallback != nil {
		return r.cleanupCallback(ctx)
	}
	return nil
}
