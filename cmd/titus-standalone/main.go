package main

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/vk/backend"
	corev1 "k8s.io/api/core/v1"

	"encoding/json"
	"os"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/tag"
	"github.com/google/go-jsonnet"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
)

type cliOptions struct {
	pod      string
	logLevel string
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
			Name:        "pod",
			Value:       "pod.jsonnet",
			Destination: &options.pod,
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

	vm := jsonnet.MakeVM()
	podJSON, err := vm.EvaluateFile(options.pod)
	if err != nil {
		return fmt.Errorf("Unable to load pod JSON: %w", err)
	}
	var pod corev1.Pod
	err = json.Unmarshal([]byte(podJSON), &pod)
	if err != nil {
		return fmt.Errorf("Could not deserialize pod JSON: %w", err)
	}

	rp, err := docker.NewDockerRuntime(ctx, m, *dockerCfg, *cfg)
	if err != nil {
		return fmt.Errorf("cannot create Titus executor: %w", err)
	}

	b, err := backend.NewBackend(ctx, rp, &pod, cfg, m)
	if err != nil {
		return fmt.Errorf("Could not instantiate backend: %w", err)
	}

	err = b.RunWithStatusFile(ctx, os.Stdout)
	if err != nil {
		return fmt.Errorf("Could not start container: %w", err)
	}

	return nil
}
