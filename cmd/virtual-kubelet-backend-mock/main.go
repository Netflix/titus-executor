package main

import (
	"context"
	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runner"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/Netflix/titus-executor/vk/backend"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"gopkg.in/urfave/cli.v1"
	"sync"
	"time"

	"os"
)

const (
	prepareTime = "github.com.netflix.titus.executor/prepareTime"
	runTime = "github.com.netflix.titus.executor/runTime"
	killTime = "github.com.netflix.titus.executor/killTime"
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

	runtime := func(ctx context.Context, cfg config.Config) (runtimeTypes.Runtime, error) {
		rm := &runtimeMock{}

		var timer *time.Timer
		if rt, ok := pod.Annotations[runTime]; ok {
			if dur, err := time.ParseDuration(rt); err != nil {
				log.G(ctx).WithError(err).Error("Could not parse duration")
				return nil, err
			} else {
				timer = time.AfterFunc(dur, func() {
					rm.statusChan<- runtimeTypes.StatusMessage{
						Status: runtimeTypes.StatusFinished,
						Msg:    "Slept, and completed",
					}
				})
			}
		}

		rm.ctx = ctx
		rm.prepareCallback = func(ctx2 context.Context) error {
				if t, ok := pod.Annotations[prepareTime]; ok {
					if dur, err := time.ParseDuration(t); err != nil {
						return err
					} else {
						time.Sleep(dur)
					}
				}
				return nil
			}
		rm.killCallback = func(c *runtimeTypes.Container) error {
			if timer != nil {
				timer.Stop()
			}
			if t, ok := pod.Annotations[killTime]; ok {
				if dur, err := time.ParseDuration(t); err != nil {
					return err
				} else {
					time.Sleep(dur)
				}
			}
			return nil
		}
		return rm, nil
	}

	cfg, _ := config.NewConfig()

	mockRunner, err := runner.WithRuntime(ctx, metrics.Discard, runtime, &uploader.Uploaders{}, *cfg)

	err = backend.RunWithBackend(ctx, mockRunner, pipe, pod)
	if err != nil {
		log.G(ctx).WithError(err).Fatal("Could not run container")
	}

	return err
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
