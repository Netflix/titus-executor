package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"expvar"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"time"

	"contrib.go.opencensus.io/exporter/zipkin"
	spectator "github.com/Netflix/spectator-go"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/logsutil"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/golang/protobuf/jsonpb"
	datadog "github.com/netflix-skunkworks/opencensus-go-exporter-datadog"
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
	atlasAddrFlagName            = "atlas-addr"
	statsdAddrFlagName           = "statsd-addr"
	zipkinURLFlagName            = "zipkin"
	debugAddressFlagName         = "debug-address"
	gcTimeoutFlagName            = "gc-timeout"
	maxIdleConnectionsFlagName   = "max-idle-connections"
	refreshIntervalFlagName      = "refresh-interval"
	maxOpenConnectionsFlagName   = "max-open-connections"
	maxConcurrentRefreshFlagName = "max-concurrent-refresh"

	sslCertFlagName         = "ssl-cert"
	sslPrivateKeyFlagName   = "ssl-private-key"
	sslCAFlagName           = "ssl-ca"
	sslTitusAgentCAFlagName = "ssl-titusagent-ca"

	enabledLongLivedTasksFlagName = "enabled-long-lived-tasks"
	enabledTaskLoopsFlagName      = "enabled-task-loops"
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

func addNonEmpty(tags map[string]string, key string, envVar string) {
	if value := os.Getenv(envVar); value != "" {
		tags[key] = value
	}
}

func getCommonTags() map[string]string {
	commonTags := map[string]string{}
	addNonEmpty(commonTags, "nf.app", "NETFLIX_APP")
	addNonEmpty(commonTags, "nf.asg", "NETFLIX_AUTO_SCALE_GROUP")
	addNonEmpty(commonTags, "nf.cluster", "NETFLIX_CLUSTER")
	addNonEmpty(commonTags, "nf.node", "NETFLIX_INSTANCE_ID")
	addNonEmpty(commonTags, "nf.region", "EC2_REGION")
	addNonEmpty(commonTags, "nf.vmtype", "EC2_INSTANCE_TYPE")
	addNonEmpty(commonTags, "nf.zone", "EC2_AVAILABILITY_ZONE")
	addNonEmpty(commonTags, "nf.stack", "NETFLIX_STACK")
	addNonEmpty(commonTags, "nf.account", "EC2_OWNER_ID")
	return commonTags
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
			view.SetReportingPeriod(time.Second * 1)

			if atlasAddr := v.GetString(atlasAddrFlagName); atlasAddr != "" {
				config := &spectator.Config{
					Frequency:  5 * time.Second,
					Timeout:    1 * time.Second,
					BatchSize:  10000,
					Uri:        atlasAddr,
					CommonTags: getCommonTags(),
				}
				registry := spectator.NewRegistry(config)

				if err := registry.Start(); err != nil {
					return err
				}
				view.RegisterExporter(newSpectatorGoExporter(registry))
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

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := setupDebugServer(ctx, v.GetString("debug-address")); err != nil {
				return err
			}

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

			go collectDBMetrics(ctx, conn)

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
					zipkinHTTP.BatchSize(1000),
					zipkinHTTP.MaxBacklog(100000),
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

			tlsConfig, err := getTLSConfig(ctx, v.GetString(sslCertFlagName), v.GetString(sslPrivateKeyFlagName), v.GetString(sslCAFlagName), v.GetString(sslTitusAgentCAFlagName))
			if err != nil {
				return errors.Wrap(err, "Could not generate TLS Config")
			}

			titusAgentCACertPool := x509.NewCertPool()
			if s := v.GetString(sslTitusAgentCAFlagName); s != "" {
				data, err := ioutil.ReadFile(s)
				if err != nil {
					return errors.Wrap(err, "Could not read file")
				}
				titusAgentCACertPool.AppendCertsFromPEM(data)
			}

			return service.Run(ctx, &service.Config{
				Listener:             listener,
				DB:                   conn,
				Key:                  signingKey,
				MaxConcurrentRefresh: v.GetInt64(maxConcurrentRefreshFlagName),
				GCTimeout:            v.GetDuration(gcTimeoutFlagName),
				ReconcileInterval:    v.GetDuration("reconcile-interval"),
				RefreshInterval:      v.GetDuration(refreshIntervalFlagName),
				TLSConfig:            tlsConfig,
				TitusAgentCACertPool: titusAgentCACertPool,

				EnabledLongLivedTasks: v.GetStringSlice(enabledLongLivedTasksFlagName),
				EnabledTaskLoops:      v.GetStringSlice(enabledTaskLoopsFlagName),
			})
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if dd != nil {
				dd.Stop()
			}
		},
	}

	rootCmd.Flags().String("address", ":7001", "Listening address")
	rootCmd.Flags().String("signingkey", "", "The (file) location of the root signing key")
	rootCmd.Flags().String(sslPrivateKeyFlagName, "", "The SSL Private Key")
	rootCmd.Flags().String(sslCertFlagName, "", "The SSL Certificate")
	rootCmd.Flags().String(sslCAFlagName, "", "General SSL CA")
	rootCmd.Flags().String(sslTitusAgentCAFlagName, "", "Titus Agent CA")
	rootCmd.Flags().Duration(gcTimeoutFlagName, 2*time.Minute, "How long must an IP be idle before we reclaim it")
	rootCmd.Flags().Duration("reconcile-interval", 5*time.Minute, "How often to reconcile")
	rootCmd.Flags().Duration(refreshIntervalFlagName, 60*time.Second, "How often to refresh IPs")
	rootCmd.Flags().StringSlice(enabledTaskLoopsFlagName, service.GetTaskLoopTaskNames(), "Enabled task loops")
	rootCmd.Flags().StringSlice(enabledLongLivedTasksFlagName, service.GetLongLivedTaskNames(), "Enabled long lived tasks")

	rootCmd.PersistentFlags().String(debugAddressFlagName, ":7003", "Address for zpages, pprof")
	rootCmd.PersistentFlags().String(statsdAddrFlagName, "", "Statsd server address")
	rootCmd.PersistentFlags().String(atlasAddrFlagName, "", "Atlas aggregator address")
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug logging")
	rootCmd.PersistentFlags().Bool("journald", true, "Log exclusively to Journald")
	rootCmd.PersistentFlags().String(zipkinURLFlagName, "", "URL To send Zipkin spans to")
	rootCmd.PersistentFlags().String("dburl", "postgres://localhost/titusvpcservice?sslmode=disable", "Connection String for database")
	rootCmd.PersistentFlags().Bool("dbiam", false, "Generate IAM credentials for database")
	rootCmd.PersistentFlags().String("region", "", "Region of the database")
	rootCmd.PersistentFlags().Int(maxIdleConnectionsFlagName, 100, "SetMaxIdleConns sets the maximum number of connections in the idle connection pool for the database")
	rootCmd.PersistentFlags().Int(maxOpenConnectionsFlagName, 200, "Maximum number of open connections allows to open to the database")
	rootCmd.PersistentFlags().Int64(maxConcurrentRefreshFlagName, 10, "The number of maximum concurrent refreshes to allow")
	rootCmd.AddCommand(migrateCommand(ctx, v))
	rootCmd.AddCommand(generateKeyCommand(ctx, v))

	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}

	bindVariables(v)
	v.AutomaticEnv()

	err := rootCmd.Execute()
	if ctx.Err() != nil {
		logger.G(ctx).Info("Shutting down gracefully")
	} else if err != nil {
		logger.G(ctx).WithError(err).Fatal("Failed")
	}
}

func bindVariables(v *pkgviper.Viper) {

	if err := v.BindEnv(statsdAddrFlagName, "STATSD_ADDR"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(zipkinURLFlagName, "ZIPKIN"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(debugAddressFlagName, "DEBUG_ADDRESS"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(atlasAddrFlagName, "ATLAS_ADDR"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(gcTimeoutFlagName, "GC_TIMEOUT"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(maxIdleConnectionsFlagName, "DB_MAX_IDLE_CONNECTIONS"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(refreshIntervalFlagName, "REFRESH_INTERVAL"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(sslPrivateKeyFlagName, "SSL_PRIVATE_KEY"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(sslCertFlagName, "SSL_CERT"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(sslCAFlagName, "SSL_CA"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(sslTitusAgentCAFlagName, "SSL_TITUSAGENT_CA"); err != nil {
		panic(err)
	}

	v.AutomaticEnv()

	if err := v.BindEnv(maxOpenConnectionsFlagName, "MAX_OPEN_CONNECTIONS"); err != nil {
		panic(err)
	}

	if err := v.BindEnv(maxConcurrentRefreshFlagName, "MAX_CONCURRENT_REFRESH"); err != nil {
		panic(err)
	}

}

func getTLSConfig(ctx context.Context, certificateFile, privateKey string, trustedCerts ...string) (*tls.Config, error) {
	if certificateFile == "" && privateKey == "" {
		return nil, nil
	}

	certPool := x509.NewCertPool()
	for _, cert := range trustedCerts {
		logger.G(ctx).WithField("cert", cert).Debug("Loading certificate")
		data, err := ioutil.ReadFile(cert)
		if err != nil {
			return nil, err
		}
		ok := certPool.AppendCertsFromPEM(data)
		if !ok {
			return nil, fmt.Errorf("Cannot load TLS Certificate from %s", cert)
		}
	}

	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certificateFile, privateKey)
			return &cert, err
		},
		ClientCAs:  certPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}
