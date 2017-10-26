package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/quitelite-client-go/properties"
	log "github.com/sirupsen/logrus"
	"github.com/Netflix/titus-executor/config"
	titusExecutor "github.com/Netflix/titus-executor/executor"
	"github.com/Netflix/titus-executor/executor/drivers/mesos"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/tag"
	"github.com/Netflix/titus-executor/uploader"
)

func init() {
	log.SetOutput(ioutil.Discard)
	logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
}

func setupLogging() {
	dp := properties.NewDynamicProperty(context.Background(), "titus.executor.logLevel", "info", "", nil)
	defer dp.Stop()
	for val := range dp.C {
		if valStr, err := val.AsString(); err != nil {
			log.Error("Cannot set log level: ", err)
		} else if valStr == "debug" {
			log.SetLevel(log.DebugLevel)
		} else if valStr == "info" {
			log.SetLevel(log.InfoLevel)
		} else {
			log.Errorf("Received log level %s from dynamic property, unknown", valStr)
		}
	}
}

func main() {
	// avoid os.Exit as much as possible to let deferred functions run
	if err := mainWithError(); err != nil {
		log.Fatal(err)
	}
}

func mainWithError() error {
	defer log.Info("titus executor terminated")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error
	// Don't specify a file so config loads with the default JSON config
	config.Load(ctx, "")

	go setupLogging()

	var m metrics.Reporter
	switch config.DevWorkspace().DisableMetrics {
	case true:
		m = metrics.Discard
	default:
		m = metrics.New(ctx, log.StandardLogger(), tag.Defaults)
		defer m.Flush()
	}

	// Create the Titus executor
	var logUploaders *uploader.Uploaders
	if logUploaders, err = uploader.NewUploaders(config.Uploaders().Log); err != nil {
		return fmt.Errorf("Cannot create log uploaders: %v", err)
	}

	executor, err := titusExecutor.New(m, logUploaders)
	if err != nil {
		return fmt.Errorf("Cannot create Titus executor: %v", err)
	}

	mesosDriverWrapper, err := titusmesosdriver.New(m, executor)
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
