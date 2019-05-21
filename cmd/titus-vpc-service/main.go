package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/Netflix/titus-executor/logger"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/vpc/service"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

var debug bool
var listenAddr string
var statsdAddr string

func init() {
	flag.BoolVar(&debug, "debug", false, "Turn on debug logging")
	flag.StringVar(&listenAddr, "address", ":7001", "Listening address")
	flag.StringVar(&statsdAddr, "statsd-address", "", "Statsd server address")
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flag.Parse()
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
	}
	ctx = logger.WithLogger(ctx, logrus.StandardLogger())

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, unix.SIGTERM, unix.SIGINT)
		sig := <-c
		logrus.WithField("signal", sig.String()).Info("Terminating with signal")
		cancel()

		// TODO: Kill self after 30 seconds
	}()

	svc := service.Server{
		ListenAddr: listenAddr,
	}
	svc.Metrics, _ = statsd.NewWithWriter(&discard{})

	if statsdAddr != "" {
		metrics, err := statsd.New(statsdAddr)
		if err != nil {
			logrus.WithError(err).Fatal("Could not setup client")
		}
		metrics.Namespace = "titus.vpc.service."
		svc.Metrics = metrics
	}

	svc.Run(ctx)
}

type discard struct {
}

func (discard) Write(data []byte) (n int, err error) {
	return len(data), nil
}

func (discard) SetWriteTimeout(time.Duration) error {
	return nil
}

func (discard) Close() error {
	return nil
}
