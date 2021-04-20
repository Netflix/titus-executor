package main

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/metadataserver/inject"
	log2 "github.com/Netflix/titus-executor/utils/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func main() {
	log2.MaybeSetupLoggerIfOnJournaldAvailable()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logruslogger := logrus.New()
	ctx = logger.WithLogger(ctx, logruslogger)

	v := pkgviper.New()
	rootCmd := &cobra.Command{
		Args: cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				panic(err)
			}

			switch level := v.GetString("log-level"); level {
			case "info":
				logruslogger.SetLevel(logrus.InfoLevel)

			case "debug":
				logruslogger.SetLevel(logrus.DebugLevel)
			default:
				return fmt.Errorf("Cannot parse log-level: %q", level)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return inject.Inject(ctx, v.GetString("titus-pid-1-dir"), args)
		},
	}
	rootCmd.Flags().String("titus-pid-1-dir", "", "Listening address")
	rootCmd.PersistentFlags().String("log-level", "info", "Log Level")

	if err := v.BindPFlags(rootCmd.PersistentFlags()); err != nil {
		panic(err)
	}
	if err := v.BindEnv("titus-pid-1-dir", "TITUS_PID_1_DIR"); err != nil {
		panic(err)
	}

	err := rootCmd.Execute()
	if err != nil {
		panic(err)
	}
}
