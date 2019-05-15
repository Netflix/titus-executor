package main

import (
	"context"
	"fmt"
	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"

	"github.com/Netflix/titus-executor/uploader"
	"github.com/Netflix/titus-executor/vk/backend"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"gopkg.in/urfave/cli.v1"
	"time"

	"os"
)

func main() {
	var (
		statusfd    int
		podFileName string
	)

	var flags = []cli.Flag{
		cli.StringFlag{
			Name: "pod",
			Destination:&podFileName,
			Usage: "The location of the pod spec file (json-ish)",
		},
		cli.IntFlag{
			Name: "status-fd",
			Destination:&statusfd,
			Value: 1, //stdout
			Usage: "The file descriptor to write status messages to",
		},

	}
	app := cli.NewApp()
	app.Name = "titus-executor"
	// avoid os.Exit as much as possible to let deferred functions run
	defer time.Sleep(1 * time.Second)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(flags, dockerCfgFlags...)

	cfg, cfgFlags := config.NewConfig()
	app.Flags = append(app.Flags, cfgFlags...)
	app.Action = func(c *cli.Context) error {
		if err := mainWithError(podFileName, statusfd, dockerCfg, cfg); err != nil {
			return cli.NewExitError(err, 1)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}

}

func mainWithError(podFileName string, statusfd int, dockerCfg *docker.Config, cfg *config.Config) error {
	logrus.SetLevel(logrus.DebugLevel)
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
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("name", pod.Name))

	log.G(ctx).WithField("pod", pod).Debug("Got pod")
	logUploaders := uploader.NewUploadersFromUploaderArray([]uploader.Uploader{})

	dockerRunner, err := runner.New(ctx, metrics.Discard, logUploaders, *cfg, *dockerCfg)
	if err != nil {
		return fmt.Errorf("Cannot create Titus executor: %v", err)
	}

	err = backend.RunWithBackend(ctx, dockerRunner, statuses, pod)
	if err != nil {
		log.G(ctx).WithError(err).Fatal("Could not run container")
	}
	return nil
}
