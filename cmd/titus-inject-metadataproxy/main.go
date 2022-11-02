package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/cmd/common"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/metadataserver/inject"
	log2 "github.com/Netflix/titus-executor/utils/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func main() {
	log2.MaybeSetupLoggerIfOnJournaldAvailable()
	go common.HandleQuitSignal()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logruslogger := logrus.New()
	ctx = logger.WithLogger(ctx, logruslogger)

	v := pkgviper.New()
	rootCmd := &cobra.Command{
		Args: cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := v.BindEnv("titus-pid-1-dir", "TITUS_PID_1_DIR"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
