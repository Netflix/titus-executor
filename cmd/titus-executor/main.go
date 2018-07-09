package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/drivers/mesos"
	"github.com/Netflix/titus-executor/executor/runner"
	"github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/properties"
	"github.com/Netflix/titus-executor/tag"
	"github.com/Netflix/titus-executor/uploader"
	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
	"gopkg.in/urfave/cli.v1/altsrc"
)

func init() {
	log.SetOutput(ioutil.Discard)
	logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
}

var logLevel string

func setupLogging() {
	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)

	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.Errorf("Received log level %s from dynamic property, unknown", logLevel)

	}
}

var flags = []cli.Flag{
	cli.BoolFlag{Name: "disable-quitelite"},
	cli.StringFlag{Name: " quitelite-url"},
	cli.StringFlag{
		Name:        "titus.executor.logLevel",
		Value:       "info",
		Destination: &logLevel,
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "titus-executor"
	// avoid os.Exit as much as possible to let deferred functions run
	defer time.Sleep(1 * time.Second)

	dockerCfg, dockerCfgFlags := docker.NewConfig()
	app.Flags = append(flags, dockerCfgFlags...)

	cfg, cfgFlags := config.NewConfig()
	app.Flags = append(app.Flags, cfgFlags...)
	app.Action = func(c *cli.Context) error {
		return cli.NewExitError(mainWithError(c, dockerCfg, cfg), 1)
	}

	altsrc.InitInputSourceWithContext(app.Flags, properties.NewQuiteliteSource("disable-quitelite", "quitelite-url"))
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}

func mainWithError(c *cli.Context, dockerCfg *docker.Config, cfg *config.Config) error {
	defer log.Info("titus executor terminated")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	// Don't specify a file so config loads with the default JSON config

	go setupLogging()

	var m metrics.Reporter
	switch cfg.DisableMetrics {
	case true:
		m = metrics.Discard
	default:
		m = metrics.New(ctx, log.StandardLogger(), tag.Defaults)
		defer m.Flush()
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

	mesosDriverWrapper, err := titusmesosdriver.New(m, runner)
	if err != nil {
		return fmt.Errorf("Unable to create the Mesos driver: %v", err)
	}

	if err = mesosDriverWrapper.Start(); err != nil {
		return fmt.Errorf("Unable to start the Mesos driver: %v", err)
	}

	go handleTerminationSignals(mesosDriverWrapper)

	if err = mesosDriverWrapper.Join(); err != nil {
		return fmt.Errorf("Unable to join on Mesos driver: %v", err)
	}
	return nil
}

func handleTerminationSignals(driver *titusmesosdriver.TitusMesosDriver) {
	term := make(chan os.Signal, 1) // buffered so we don't miss a signal
	signal.Notify(term, shutdownSignals()...)
	for termSig := range term {
		log.Infof(
			"Received termination signal %s, attempting to gracefully shutdown the executor...",
			termSig.String(),
		)
		if err := driver.Stop(); err != nil {
			log.Error(err)
		}
		// TODO(fabio): once we migrate to Go 1.8, gracefully shutdown the HTTP server
	}
}
