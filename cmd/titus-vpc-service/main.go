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

	"github.com/Netflix/titus-executor/utils/log"

	"github.com/Netflix/titus-executor/vpc"

	spectator "github.com/Netflix/spectator-go"
	"github.com/Netflix/titus-executor/cmd/common"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service"
	"github.com/Netflix/titus-executor/vpc/service/config"
	datadog "github.com/netflix-skunkworks/opencensus-go-exporter-datadog"
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
	go common.HandleQuitSignal()
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
				log.MaybeSetupLoggerIfOnJournaldAvailable()
			}
			view.SetReportingPeriod(time.Second * 1)

			if atlasAddr := v.GetString(config.AtlasAddrFlagName); atlasAddr != "" {
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
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := setupDebugServer(ctx, v.GetString(config.DebugAddressFlagName)); err != nil {
				return err
			}

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

			vpcServiceConfig, err := service.NewConfig(ctx, v)
			if err != nil {
				return errors.Wrap(err, "Failed to create configs for VPC service")
			}
			return service.Run(ctx, vpcServiceConfig, v.GetString("address"))
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if dd != nil {
				dd.Stop()
			}
		},
	}

	rootCmd.Flags().String("address", ":7001", "Listening address")
	rootCmd.Flags().String("signingkey", "", "The (file) location of the root signing key")
	rootCmd.Flags().String(config.SslPrivateKeyFlagName, "", "The SSL Private Key")
	rootCmd.Flags().String(config.SslCertFlagName, "", "The SSL Certificate")
	rootCmd.Flags().String(config.SslCAFlagName, "", "General SSL CA")
	rootCmd.Flags().Duration(config.ReconcileIntervalFlagName, 5*time.Minute, "How often to reconcile")
	rootCmd.Flags().Duration(config.TableMetricsIntervalFlagName, 5*time.Minute, "How often to collect DB table metrics")
	rootCmd.Flags().StringSlice(config.EnabledTaskLoopsFlagName, service.GetTaskLoopTaskNames(), "Enabled task loops")
	rootCmd.Flags().StringSlice(config.EnabledLongLivedTasksFlagName, service.GetLongLivedTaskNames(), "Enabled long lived tasks")
	rootCmd.Flags().String(config.TrunkENIDescriptionFlagName, vpc.DefaultTrunkNetworkInterfaceDescription, "The description for trunk interfaces")
	rootCmd.Flags().String(config.BranchENIDescriptionFlagName, vpc.DefaultBranchNetworkInterfaceDescription, "The description for branch interfaces")
	rootCmd.Flags().String(config.SubnetCIDRReservationFlagName, vpc.DefaultSubnetCIDRReservationDescription, "The description of CIDRs to use for SCRs")
	rootCmd.Flags().String(config.WorkerRoleFlagName, "", "The role which to assume into to do work")
	rootCmd.Flags().Int(config.MaxConcurrentRequestsFlagName, 100, "Maximum concurrent gRPC requests to allow")

	rootCmd.PersistentFlags().String(config.DebugAddressFlagName, ":7003", "Address for zpages, pprof")
	rootCmd.PersistentFlags().String(config.AtlasAddrFlagName, "", "Atlas aggregator address")
	rootCmd.PersistentFlags().Bool("debug", false, "Turn on debug logging")
	rootCmd.PersistentFlags().Bool("journald", true, "Log exclusively to Journald")
	rootCmd.PersistentFlags().String(config.ZipkinURLFlagName, "", "URL To send Zipkin spans to")
	rootCmd.PersistentFlags().String(config.DBURLFlagName, "postgres://localhost/titusvpcservice?sslmode=disable", "Connection String for database")
	rootCmd.PersistentFlags().Int(config.MaxIdleConnectionsFlagName, 100, "SetMaxIdleConns sets the maximum number of connections in the idle connection pool for the database")
	rootCmd.PersistentFlags().Int(config.MaxOpenConnectionsFlagName, 200, "Maximum number of open connections allows to open to the database")
	rootCmd.PersistentFlags().Int64(config.MaxConcurrentRefreshFlagName, 10, "The number of maximum concurrent refreshes to allow")
	rootCmd.AddCommand(migrateCommand(ctx, v))
	rootCmd.AddCommand(generateKeyCommand(ctx, v))
	rootCmd.AddCommand(fixAllocations(ctx, v))

	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}

	bindVariables(v)

	err := rootCmd.Execute()
	if ctx.Err() != nil {
		logger.G(ctx).Info("Shutting down gracefully")
	} else if err != nil {
		logger.G(ctx).WithError(err).Fatal("Failed")
	}
}

func bindVariable(v *pkgviper.Viper, key, env string) {
	if err := v.BindEnv(key, env); err != nil {
		panic(err)
	}
}

func bindVariables(v *pkgviper.Viper) {
	bindVariable(v, config.DBURLFlagName, "DBURL")
	bindVariable(v, config.ZipkinURLFlagName, "ZIPKIN")
	bindVariable(v, config.DebugAddressFlagName, "DEBUG_ADDRESS")
	bindVariable(v, config.AtlasAddrFlagName, "ATLAS_ADDR")
	bindVariable(v, config.MaxIdleConnectionsFlagName, "DB_MAX_IDLE_CONNECTIONS")
	bindVariable(v, config.SslPrivateKeyFlagName, "SSL_PRIVATE_KEY")
	bindVariable(v, config.SslCertFlagName, "SSL_CERT")
	bindVariable(v, config.SslCAFlagName, "SSL_CA")
	bindVariable(v, config.MaxOpenConnectionsFlagName, "MAX_OPEN_CONNECTIONS")
	bindVariable(v, config.MaxConcurrentRefreshFlagName, "MAX_CONCURRENT_REFRESH")
	bindVariable(v, config.WorkerRoleFlagName, "WORKER_ROLE")
	bindVariable(v, config.MaxConcurrentRequestsFlagName, "MAX_CONCURRENT_REQUESTS")
	bindVariable(v, config.TableMetricsIntervalFlagName, "TABLE_METRICS_INTERVAL")
	// TODO(hli): Consider removing it as it's dangerous. We don't know what env variables are automatically bound by this.
	v.AutomaticEnv()
}
