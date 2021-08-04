package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"contrib.go.opencensus.io/exporter/zipkin"
	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/tag"
	log2 "github.com/Netflix/titus-executor/utils/log"
	"github.com/Netflix/titus-executor/vk/backend"
	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"go.opencensus.io/trace"
	v1 "k8s.io/api/core/v1"
)

type commandConfig struct {
	// runtime dir will have pod.json
	// and be populated with state.json
	// All other file names are meant to be ignored.
	runtimeDir string
	journald   bool
	zipkin     string
	debug      bool
}

func main() {
	mainCfg := commandConfig{}
	var flags = []cli.Flag{
		cli.StringFlag{
			Name:        "runtime-dir",
			Destination: &mainCfg.runtimeDir,
			Usage:       "The location of the pod spec file (json-ish)",
			Value:       "/run/titus-executor/default__",
		},
		cli.BoolTFlag{
			Name:        "journald",
			Usage:       "Enable logging to journald",
			Destination: &mainCfg.journald,
		},
		cli.StringFlag{
			Name:        "zipkin",
			Destination: &mainCfg.zipkin,
			EnvVar:      "ZIPKIN",
		},
		cli.BoolFlag{
			Name:        "debug",
			Destination: &mainCfg.debug,
			EnvVar:      "DEBUG",
		},
	}

	app := cli.NewApp()
	app.Name = "titus-virtual-kubelet-backend"
	// avoid os.Exit as much as possible to let deferred functions run
	defer time.Sleep(1 * time.Second)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(flags, dockerCfgFlags...)

	cfg, cfgFlags := config.NewConfig()
	app.Flags = append(app.Flags, cfgFlags...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if mainCfg.journald {
		log2.MaybeSetupLoggerIfOnJournaldAvailable()
	}

	logrusLogger := logrus.StandardLogger()
	ctx = logger.WithLogger(ctx, logrusLogger)

	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
	m := metrics.New(ctx, logrus.StandardLogger(), tag.Defaults)
	m = runner.NewReporter(m)
	defer m.Flush()

	app.Action = func(c *cli.Context) error {
		if mainCfg.debug {
			logrus.SetLevel(logrus.DebugLevel)
			logrusLogger.Debug("enabled debug logging")
		}
		cfg.RuntimeDir = mainCfg.runtimeDir

		if err := mainWithError(ctx, dockerCfg, cfg, &mainCfg, m); err != nil {
			return cli.NewExitError(err, 1)
		}
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}

}

func mainWithError(ctx context.Context, dockerCfg *docker.Config, cfg *config.Config, mainCfg *commandConfig, m metrics.Reporter) error {
	var ew *exporterWrapper
	if mainCfg.zipkin != "" {
		reporter := zipkinHTTP.NewReporter(mainCfg.zipkin,
			zipkinHTTP.BatchInterval(time.Second*5),
			zipkinHTTP.BatchSize(10),
			zipkinHTTP.MaxBacklog(100000),
		)
		hostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("Unable to fetch hostname: %w", err)
		}
		endpoint, err := openzipkin.NewEndpoint("titus-executor", hostname)
		if err != nil {
			return fmt.Errorf("Failed to create the local zipkinEndpoint: %w", err)
		}
		logger.G(ctx).WithField("endpoint", endpoint).WithField("url", mainCfg.zipkin).Info("Setting up tracing")
		exporter := zipkin.NewExporter(reporter, endpoint)
		ew = &exporterWrapper{exporter: exporter}
		trace.RegisterExporter(ew)
		defer func() {
			reporterErr := reporter.Close()
			if reporterErr != nil {
				logger.G(ctx).WithError(err).Error("Unable to close reporter")
			}
		}()
	}

	logger.G(ctx).WithField("cfg", logger.ShouldJSON(ctx, *cfg)).WithField("dockerCfg", logger.ShouldJSON(ctx, *dockerCfg)).Debug("Loaded config and docker config")

	var pod v1.Pod
	podFileName := filepath.Join(mainCfg.runtimeDir, "pod.json")
	data, err := ioutil.ReadFile(podFileName)
	if err != nil {
		return fmt.Errorf("Unable to read pod file %q: %w", podFileName, err)
	}

	err = json.Unmarshal(data, &pod)
	if err != nil {
		return fmt.Errorf("Could not deserialize pod file: %w", err)
	}

	if ew != nil {
		ew.Lock()
		ew.taskID = pod.Name
		ew.Unlock()
	}

	logger.G(ctx).WithField("pod", pod).Debug("Got pod")

	rp, err := docker.NewDockerRuntime(ctx, m, *dockerCfg, *cfg)
	if err != nil {
		return fmt.Errorf("Cannot create Titus executor: %w", err)
	}

	b, err := backend.NewBackend(ctx, rp, &pod, cfg, m)
	if err != nil {
		return err
	}
	go func() {
		err := b.Ready(ctx)
		if err == nil {
			logger.G(ctx).Info("Notified systemd we are ready")
			notifySystemd(ctx)
		} else {
			logger.G(ctx).WithError(err).Error("Could not notify systemd we are ready")
		}
	}()

	return b.RunWithOutputDir(ctx, mainCfg.runtimeDir)
}

type exporterWrapper struct {
	sync.RWMutex
	exporter *zipkin.Exporter
	taskID   string
}

func (e *exporterWrapper) ExportSpan(s *trace.SpanData) {
	e.RLock()
	if e.taskID != "" {
		if s.Attributes == nil {
			s.Attributes = map[string]interface{}{}
		}
		s.Attributes["taskid"] = e.taskID
	}
	e.RUnlock()
	e.exporter.ExportSpan(s)
}
