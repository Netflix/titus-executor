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

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/golang/protobuf/jsonpb"

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

const (
	statsdAddrFlagName = "statsd-addr"
	zipkinURLFlagName  = "zipkin"
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
	var dd *datadog.Exporter
	rootCmd := &cobra.Command{
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if v.GetBool("debug") {
				logrus.SetLevel(logrus.DebugLevel)
				logrusLogger.SetLevel(logrus.DebugLevel)
			}
			if v.GetBool("journald") {
				logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
			}
			if statsdAddr := v.GetString(statsdAddrFlagName); statsdAddr != "" {
				logger.G(ctx).WithField(statsdAddrFlagName, statsdAddr).Info("Setting up statsd exporter")
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

			return setupDebugServer(ctx, v.GetString("debug-address"))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}

			conn, err := newConnection(ctx, v)
			if err != nil {
				return err
			}

			needsMigration, err := db.NeedsMigration(ctx, conn)
			if err != nil {
				return err
			}

			if needsMigration {
				logger.G(ctx).Fatal("Cannot startup, need to run database migrations")
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

			listener, err := net.Listen("tcp", v.GetString("address"))
			if err != nil {
				return errors.Wrap(err, "Could not setup listener")
			}
			defer listener.Close()
			logger.G(ctx).WithField("address", listener.Addr().String()).Info("Listening")

			if zipkinURL := v.GetString(zipkinURLFlagName); zipkinURL != "" {
				reporter := zipkinHTTP.NewReporter(zipkinURL,
					zipkinHTTP.BatchInterval(time.Second*5),
					zipkinHTTP.BatchSize(10000),
					zipkinHTTP.MaxBacklog(1000),
				)
				hostname, err := os.Hostname()
				if err != nil {
					return errors.Wrap(err, "Unable to fetch hostname")
				}
				endpoint, err := openzipkin.NewEndpoint("titus-vpc-service", hostname)
				if err != nil {
					return errors.Wrap(err, "Failed to create the local zipkinEndpoint")
				}
				logger.G(ctx).WithField("endpoint", endpoint).WithField("url", zipkinURL).Info("Setting up tracing")
				trace.RegisterExporter(zipkin.NewExporter(reporter, endpoint))
			}

			var signingKey vpcapi.PrivateKey
			signingKeyFile, err := os.Open(v.GetString("signingkey"))
			if err != nil {
				return errors.Wrap(err, "Failed to open signing key file")
			}

			err = jsonpb.Unmarshal(signingKeyFile, &signingKey)
			if err != nil {
				return errors.Wrap(err, "Could not deserialize key")
			}
			signingKeyFile.Close()

			return service.Run(ctx, listener, conn, signingKey)
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if dd != nil {
				dd.Stop()
			}
		},
	}

	rootCmd.Flags().String("address", ":7001", "Listening address")
	rootCmd.Flags().String("signingkey", "", "The (file) location of the root signing key")
	rootCmd.PersistentFlags().String("debug-address", ":7003", "Address for zpages, pprof")
	rootCmd.PersistentFlags().String(statsdAddrFlagName, "", "Statsd server address")
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug logging")
	rootCmd.PersistentFlags().Bool("journald", true, "Log exclusively to Journald")
	rootCmd.PersistentFlags().String(zipkinURLFlagName, "", "URL To send Zipkin spans to")
	rootCmd.PersistentFlags().String("dburl", "postgres://localhost/titusvpcservice?sslmode=disable", "Connection String for database")
	rootCmd.PersistentFlags().Bool("dbiam", false, "Generate IAM credentials for database")
	rootCmd.PersistentFlags().String("region", "", "Region of the database")

	rootCmd.AddCommand(migrateCommand(ctx, v))
	rootCmd.AddCommand(generateKeyCommand(ctx, v))

	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}

	if err := v.BindEnv(statsdAddrFlagName, "STATSD_ADDR"); err != nil {
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
