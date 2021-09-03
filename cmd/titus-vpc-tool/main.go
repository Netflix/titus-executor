package main

import (
	"context"
	"fmt"
	"os"

	"contrib.go.opencensus.io/exporter/zipkin"
	datadog "github.com/Datadog/opencensus-go-exporter-datadog"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	openzipkin "github.com/openzipkin/zipkin-go"
	"github.com/openzipkin/zipkin-go/reporter"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"github.com/wercker/journalhook"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/trace"
)

const (
	stateDirFlagName        = "state-dir"
	stateDirDefaultValue    = "/run/titus-vpc-tool"
	serviceAddrFlagName     = "service-addr"
	serviceAddrDefaultValue = "localhost:7001"
	statsdAddrFlagName      = "statsd-addr"
	zipkinURLFlagName       = "zipkin"
	// which generation of titus-vpc-tool version to use, it must be set to 1 or 2
	generationFlagName      = "generation"
	generationDefaultValue  = "v0"
	interaceSubnet          = "interface-subnet"
	interfaceAccount        = "interface-account"
	sslCAFlagName           = "ssl-ca"
	sslKeyFlagName          = "ssl-key"
	sslCertFlagName         = "ssl-cert"
	transitionNSDirFlagName = "transition-namespace-dir"
)

type instanceProviderResolver struct {
	provider identity.InstanceIdentityProvider
}

func (ipr *instanceProviderResolver) getProvider() identity.InstanceIdentityProvider {
	if ipr.provider == nil {
		panic("Error, instance identity provider not configured")
	}
	return ipr.provider
}

type instanceIdentityProviderGetter func() identity.InstanceIdentityProvider

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func main() {
	var cfgFile string

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logruslogger := logrus.New()
	ctx = logger.WithLogger(ctx, logruslogger)
	v := pkgviper.New()

	ipr := &instanceProviderResolver{}
	environmentIdentityProviderFlagSet, environmentIdentityProvider := identity.GetEnvironmentProvider(v)
	ec2IdentityProvider := identity.GetEC2Provider()
	var dd *datadog.Exporter
	var reporter reporter.Reporter
	rootCmd := &cobra.Command{
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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

			if err := view.Register(ocgrpc.DefaultClientViews...); err != nil {
				return err
			}
			trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

			if err := v.BindPFlags(cmd.Flags()); err != nil {
				panic(err)
			}
			ctx = logger.WithLogger(ctx, logger.G(ctx).WithField("command", cmd.Name()))
			level, err := logrus.ParseLevel(v.GetString("log-level"))
			if err != nil {
				return err
			}
			logruslogger.SetLevel(level)

			if v.GetBool("journald") {
				logruslogger.AddHook(&journalhook.JournalHook{})
			}

			if zipkinURL := v.GetString(zipkinURLFlagName); zipkinURL != "" {
				hostname, err := os.Hostname()
				if err != nil {
					return err
				}
				// 1. Configure exporter to export traces to Zipkin.
				endpoint, err := openzipkin.NewEndpoint("titus-vpc-tool", hostname)
				if err != nil {
					return errors.Wrap(err, "Failed to create the local zipkinEndpoint")
				}
				logger.G(ctx).WithField("endpoint", endpoint).WithField("url", zipkinURL).Info("Setting up tracing")
				reporter = zipkinHTTP.NewReporter(zipkinURL)

				ze := zipkin.NewExporter(reporter, endpoint)
				trace.RegisterExporter(ze)
			}

			switch ip := v.GetString("identity-provider"); ip {
			case "environment":
				ipr.provider = environmentIdentityProvider
			case "ec2":
				ipr.provider = ec2IdentityProvider
			default:
				return errors.Errorf("Identity provider %q not supported", ip)
			}
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if dd != nil {
				dd.Stop()
			}
			if reporter != nil {
				err := reporter.Close()
				if err != nil {
					logger.G(ctx).WithError(err).Error("Unable to close / flush reporter")
				}
			}
		},
	}

	rootCmd.PersistentFlags().AddFlagSet(environmentIdentityProviderFlagSet)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.d.yaml)")

	// So this is dumb. cobra doesn't support reading env vars. For this you have to use viper. Viper sources the
	// list of env vars from parsing the pflags within cobra.
	rootCmd.PersistentFlags().String("log-level", "info", "")
	rootCmd.PersistentFlags().Bool("journald", true, "Enable journald logging")
	rootCmd.PersistentFlags().String("identity-provider", "ec2", "How to fetch the machine's identity")
	rootCmd.PersistentFlags().String(statsdAddrFlagName, "", "Statsd server address")
	rootCmd.PersistentFlags().String(zipkinURLFlagName, "", "URL To send Zipkin spans to")

	if err := v.BindEnv(zipkinURLFlagName, "VPC_STATSD_ADDR"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(zipkinURLFlagName, "VPC_ZIPKIN"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(stateDirFlagName, "VPC_STATE_DIR"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(serviceAddrFlagName, "VPC_SERVICE_ADDR"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(generationFlagName, "VPC_SERVICE_GENERATION"); err != nil {
		panic(err)
	}
	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		panic(err)
	}
	if err := v.BindEnv(sslCAFlagName, "VPC_SSL_CA"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(sslKeyFlagName, "VPC_SSL_KEY"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(sslCertFlagName, "VPC_SSL_CERT"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(sourceOfTruthFlagName, "SOURCE_OF_TRUTH"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(assignNetworkCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(genConfCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(setupInstanceCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(setupContainercommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(teardownContainercommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(gcCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(operatorCmd(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(unassignNetworkCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(crossMountCommand(ctx, v))

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			// Use config file from the flag.
			v.SetConfigFile(cfgFile)
		}

		v.AutomaticEnv() // read in environment variables that match

		// If a config file is found, read it in.
		if err := v.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", v.ConfigFileUsed())
		}
	})
	err := rootCmd.Execute()
	if err != nil {
		logger.G(ctx).WithError(err).Fatal("Failed")
	}
}
