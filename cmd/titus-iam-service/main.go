package main

import (
	"context"
	"expvar"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"time"

	"contrib.go.opencensus.io/exporter/zipkin"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/metadataserver/service"
	"github.com/Netflix/titus-executor/utils/log"
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

const (
	zipkinURLFlagName    = "zipkin"
	debugAddressFlagName = "debug-address"
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
	mux.Handle("/debug/vars", expvar.Handler())
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

	logrusLogger := logrus.StandardLogger()
	ctx = logger.WithLogger(ctx, logrusLogger)

	v := pkgviper.New()

	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
	rootCmd := &cobra.Command{
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			v.SetEnvPrefix("TITUS_IAM_SERVICE")
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			v.AutomaticEnv()

			if v.GetBool("debug") {
				logrus.SetLevel(logrus.DebugLevel)
				logrusLogger.SetLevel(logrus.DebugLevel)
			}
			if v.GetBool("journald") {
				log.MaybeSetupLoggerIfOnJournaldAvailable()
			}
			view.SetReportingPeriod(time.Second * 1)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := setupDebugServer(ctx, v.GetString("debug-address")); err != nil {
				return err
			}

			go func() {
				c := make(chan os.Signal, 1)
				signal.Notify(c, unix.SIGTERM, unix.SIGINT)
				sig := <-c
				logrus.WithField("signal", sig.String()).Info("Terminating with signal")
				cancel()
				select {
				case <-time.After(time.Second * 30):
				case sig = <-c:
					logrus.WithField("signal", sig.String()).Info("Received another signal. Immediately terminating")
				}

				logrus.Fatal("System did not gracefully terminate")
				_ = unix.Kill(0, unix.SIGKILL)
			}()

			listener, err := net.Listen("tcp", v.GetString("address"))
			if err != nil {
				return errors.Wrap(err, "Could not setup listener")
			}
			defer listener.Close()
			logger.G(ctx).WithField("address", listener.Addr().String()).Info("Listening")

			if zipkinURL := v.GetString(zipkinURLFlagName); zipkinURL != "" {
				reporter := zipkinHTTP.NewReporter(zipkinURL,
					zipkinHTTP.BatchInterval(time.Second*5),
					zipkinHTTP.BatchSize(1000),
					zipkinHTTP.MaxBacklog(100000),
				)
				hostname, err := os.Hostname()
				if err != nil {
					return errors.Wrap(err, "Unable to fetch hostname")
				}
				endpoint, err := openzipkin.NewEndpoint("titus-iam-service", hostname)
				if err != nil {
					return errors.Wrap(err, "Failed to create the local zipkinEndpoint")
				}
				logger.G(ctx).WithField("endpoint", endpoint).WithField("url", zipkinURL).Info("Setting up tracing")
				trace.RegisterExporter(zipkin.NewExporter(reporter, endpoint))
			}

			return service.Run(ctx, service.Config{
				Listener:        listener,
				OpenPolicyAgent: v.GetString("open-policy-agent"),
				ClientCA:        v.GetString("client-ca"),
				Region:          v.GetString("region"),
				SSLKey:          v.GetString("ssl-key"),
				SSLCert:         v.GetString("ssl-cert"),
			})
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			// TODO: Add metrics flush
		},
	}

	rootCmd.Flags().String("address", ":7001", "Listening address")
	rootCmd.Flags().String("region", "", "Region of STS service to connect to")
	rootCmd.Flags().String("ssl-key", "", "The SSL Private Key")
	rootCmd.Flags().String("ssl-cert", "", "The SSL Certificate")
	rootCmd.Flags().String("client-ca", "", "Client accept CA file")
	rootCmd.Flags().String("open-policy-agent", "", "Open policy agent address")

	rootCmd.PersistentFlags().String(debugAddressFlagName, ":7003", "Address for zpages, pprof")
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug logging")
	rootCmd.PersistentFlags().Bool("journald", true, "Log exclusively to Journald")
	rootCmd.PersistentFlags().String(zipkinURLFlagName, "", "URL To send Zipkin spans to")

	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}

	if err := v.BindEnv("region", "EC2_REGION"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(zipkinURLFlagName, "ZIPKIN"); err != nil {
		panic(err)
	}

	err := rootCmd.Execute()
	if ctx.Err() != nil {
		logger.G(ctx).Info("Shutting down gracefully")
	} else if err != nil {
		logger.G(ctx).WithError(err).Fatal("Failed")
	}
}
