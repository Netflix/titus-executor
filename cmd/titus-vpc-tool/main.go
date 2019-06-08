package main

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/identity"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"github.com/wercker/journalhook"
)

const (
	stateDirFlagName        = "state-dir"
	stateDirDefaultValue    = "/run/titus-vpc-tool"
	serviceAddrFlagName     = "service-addr"
	serviceAddrDefaultValue = "localhost:7001"
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
	rootCmd := &cobra.Command{
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
	}

	rootCmd.PersistentFlags().AddFlagSet(environmentIdentityProviderFlagSet)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.d.yaml)")

	// So this is dumb. cobra doesn't support reading env vars. For this you have to use viper. Viper sources the
	// list of env vars from parsing the pflags within cobra.
	rootCmd.PersistentFlags().String("log-level", "info", "")
	rootCmd.PersistentFlags().Bool("journald", true, "Enable journald logging")
	rootCmd.PersistentFlags().String("identity-provider", "ec2", "How to fetch the machine's identity")

	if err := v.BindEnv(stateDirFlagName, "VPC_STATE_DIR"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(serviceAddrFlagName, "VPC_SERVICE_ADDR"); err != nil {
		panic(err)
	}
	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(allocateNetworkCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(genConfCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(setupInstanceCommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(backfilleniCommand(ctx, v))
	rootCmd.AddCommand(globalGCCommand(ctx, v))
	rootCmd.AddCommand(setupContainercommand(ctx, v, ipr.getProvider))
	rootCmd.AddCommand(gcCommand(ctx, v, ipr.getProvider))

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
