package main

import (
	"context"
	"fmt"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/tag"
	"github.com/Netflix/titus-executor/uploader"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"

	"time"

	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
)

type cliOptions struct {
	containerInfo string
	taskID        string
	mem           int64
	cpu           int64
	disk          uint64
	logLevel      string
}

func main() {
	var options cliOptions
	app := cli.NewApp()
	app.Name = "titus-standalone"
	defer time.Sleep(1 * time.Second)
	// avoid os.Exit as much as possible to let deferred functions run
	cfg, cfgFlags := config.NewConfig()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "container-info",
			Value:       "container-info.json",
			Destination: &options.containerInfo,
		},
		cli.StringFlag{
			Name:        "task-id",
			Value:       "titus-standalone-task",
			Destination: &options.taskID,
		},
		cli.Int64Flag{
			Name:        "mem",
			Value:       1024,
			Destination: &options.mem,
		},
		cli.Int64Flag{
			Name:        "cpu",
			Value:       1,
			Destination: &options.cpu,
		},
		cli.Uint64Flag{
			Name:        "disk",
			Value:       10000,
			Destination: &options.disk,
		},
		cli.StringFlag{
			Name:        "log-level",
			Value:       "info",
			Destination: &options.logLevel,
		},
	}
	app.Flags = append(app.Flags, cfgFlags...)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(app.Flags, dockerCfgFlags...)

	app.Action = func(c *cli.Context) error {
		return cli.NewExitError(mainWithError(c, dockerCfg, cfg, &options), 1)
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func mainWithError(c *cli.Context, dockerCfg *docker.Config, cfg *config.Config, options *cliOptions) error { // nolint: gocyclo
	defer log.Info("titus executor terminated")

	switch options.logLevel {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		return fmt.Errorf("Unknown log level: %s", options.logLevel)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	// Don't specify a file so config loads with the default JSON config

	var m metrics.Reporter
	switch cfg.DisableMetrics {
	case true:
		m = metrics.Discard
	default:
		m = metrics.New(ctx, log.StandardLogger(), tag.Defaults)
		defer m.Flush()
	}

	var containerInfo titus.ContainerInfo
	containerInfoFile, err := os.Open(options.containerInfo)
	if err != nil {
		return err
	}
	err = json.NewDecoder(containerInfoFile).Decode(&containerInfo)
	if err != nil {
		return err
	}

	// Create the Titus executor
	var logUploaders *uploader.Uploaders
	if logUploaders, err = uploader.NewUploaders(cfg, m); err != nil {
		return fmt.Errorf("Cannot create log uploaders: %v", err)
	}

	runner, err := runner.New(ctx, m, logUploaders, *cfg, *dockerCfg)
	if err != nil {
		return fmt.Errorf("Cannot create Titus executor: %v", err)
	}

	go func() {
		term := make(chan os.Signal, 1) // buffered so we don't miss a signal
		signal.Notify(term, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		<-term
		log.Warning("Terminating task")
		runner.Kill()
	}()
	log.Info("Starting task")
	err = runner.StartTask(options.taskID, &containerInfo, options.mem, options.cpu, options.disk)
	if err != nil {
		return err
	}
	for update := range runner.UpdatesChan {
		log.Info(update)
	}
	<-runner.StoppedChan
	log.Info("Container stopped, terminating")
	return nil
}
