package main

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"time"

	"contrib.go.opencensus.io/exporter/zipkin"
	datadog "github.com/Datadog/opencensus-go-exporter-datadog"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/vpc/service"
	openzipkin "github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"
	"go.opencensus.io/zpages"
	"golang.org/x/sys/unix"
)

func setupDebugServer(ctx context.Context, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return errors.Wrap(err, "Cannot setup listener for debug server")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	zpages.Handle(mux, "/trace")

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		err := http.Serve(listener, mux)
		if err != nil && ctx.Err() == nil {
			logger.G(ctx).WithError(err).Fatal("Debug server exited problematically")
		}
	}()

	return nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx = logger.WithLogger(ctx, logrus.StandardLogger())

	v := pkgviper.New()

	var dd *datadog.Exporter
	rootCmd := &cobra.Command{
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if v.GetBool("debug") {
				logrus.SetLevel(logrus.DebugLevel)
			}
			if v.GetBool("journald") {
				logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
			}
			if statsdAddr := v.GetString("statsd-address"); statsdAddr != "" {
				logger.G(ctx).WithField("statsd-address", statsdAddr).Info("Setting up statsd exporter")
				var err error
				dd, err = datadog.NewExporter(datadog.Options{
					StatsAddr: statsdAddr,
					Namespace: "titus.vpcService",
					OnError: func(ddErr error) {
						logger.G(ctx).WithError(ddErr).Error("Error exporting metrics")
					},
				})
				if err != nil {
					return errors.Wrap(err, "Failed to create the Datadog exporter")
				}
				view.RegisterExporter(dd)
			}

			trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

			return setupDebugServer(ctx, v.GetString("debug-address"))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			go func() {
				c := make(chan os.Signal, 1)
				signal.Notify(c, unix.SIGTERM, unix.SIGINT)
				sig := <-c
				logrus.WithField("signal", sig.String()).Info("Terminating with signal")
				cancel()
				<-time.After(time.Second * 30)
				logrus.Fatal("System did not gracefully terminate")
				_ = unix.Kill(0, unix.SIGKILL)
			}()

			svc := service.Server{}

			listener, err := net.Listen("tcp", v.GetString("address"))
			if err != nil {
				return errors.Wrap(err, "Could not setup listener")
			}
			defer listener.Close()
			logger.G(ctx).WithField("address", listener.Addr().String()).Info("Listening")

			if zipkinURL := v.GetString("zipkin"); zipkinURL != "" {
				reporter := zipkinHTTP.NewReporter(zipkinURL)
				endpoint, err := openzipkin.NewEndpoint("titus-vpc-service", listener.Addr().String())
				if err != nil {
					return errors.Wrap(err, "Failed to create the local zipkinEndpoint")
				}
				trace.RegisterExporter(zipkin.NewExporter(reporter, endpoint))
			}

			return svc.Run(ctx, listener)
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if dd != nil {
				dd.Stop()
			}
		},
	}

	rootCmd.Flags().String("address", ":7001", "Listening address")
	rootCmd.PersistentFlags().String("debug-address", ":7003", "Address for zpages, pprof")
	rootCmd.PersistentFlags().String("statsd-address", "", "Statsd server address")
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug logging")
	rootCmd.PersistentFlags().Bool("journald", true, "Log exclusively to Journald")
	rootCmd.PersistentFlags().String("zipkin", "", "URL To send Zipkin spans to")
	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}
	v.AutomaticEnv()

	err := rootCmd.Execute()
	if ctx.Err() != nil {
		logger.G(ctx).Info("Shutting down gracefully")
	} else if err != nil {
		logger.G(ctx).WithError(err).Fatal("Failed")
	}
}
