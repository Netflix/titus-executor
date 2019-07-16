package main

import (
	"context"
	"fmt"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/vk/backend"

	"time"

	"github.com/Netflix/titus-executor/uploader"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"gopkg.in/urfave/cli.v1"

	"os"
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
	app.Name = "titus-executor"
	// avoid os.Exit as much as possible to let deferred functions run
	defer time.Sleep(1 * time.Second)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(flags, dockerCfgFlags...)

	cfg, cfgFlags := config.NewConfig()
	app.Flags = append(app.Flags, cfgFlags...)
	app.Action = func(c *cli.Context) error {
		if err := mainWithError(podFileName, statusPipe, dockerCfg, cfg); err != nil {
			return cli.NewExitError(err, 1)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}

}

func mainWithError(podFileName string, statusPipe string, dockerCfg *docker.Config, cfg *config.Config) error {
	logrus.SetLevel(logrus.DebugLevel)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))
	ctx = log.WithLogger(ctx, log.L)

	log.G(ctx).Debugf("Args: %v, %v", podFileName, statusPipe)
	log.G(ctx).Debugf("os.Args[0]: %v", os.Args[0])

	podFile, err := os.Open(podFileName)
	if err != nil {
		panic(err)
	}

	pod, err := backend.PodFromFile(podFile)
	if err != nil {
		panic(err)
	}
	log.G(ctx).WithField("pod", pod.Name).Debugf("Got pod %v", pod)

	pipe, err := os.OpenFile(statusPipe, os.O_RDWR, 0600)
	if err != nil {
		panic(err)
	}
	defer pipe.Close()
	log.G(ctx).WithField("pod", pod.Name).Debugf("Got pipe %v", statusPipe)

	logUploaders := uploader.NewUploadersFromUploaderArray([]uploader.Uploader{})

	dockerRunner, err := runner.New(ctx, metrics.Discard, logUploaders, *cfg, *dockerCfg)
	if err != nil {
		return fmt.Errorf("cannot create Titus executor: %v", err)
	}

	err = backend.RunWithBackend(ctx, dockerRunner, pipe, pod)
	if err != nil {
		log.G(ctx).WithError(err).Fatal("Could not run container")
	}
	return nil
}
