package main

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/vpc/globalgc"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func globalGCCommand(ctx context.Context, v *pkgviper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "globalgc",
		Short: "Garbage collect detached ENIs",
		RunE: func(cmd *cobra.Command, args []string) error {
			return globalgc.GlobalGC(ctx, v.GetDuration("timeout"), v.GetDuration("time-since-creation"))
		},
	}

	// TODO: Add cross-account run
	cmd.Flags().Duration("timeout", 15*time.Minute, "How long to run the GC for")
	cmd.Flags().Duration("time-since-creation", 30*time.Minute, "How long an ENI has to be created before we will clean it up")

	return cmd
}
