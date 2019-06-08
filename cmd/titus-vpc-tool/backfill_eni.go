package main

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/vpc/backfilleni"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func backfilleniCommand(ctx context.Context, v *pkgviper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "For ENIs which do not have a creation timestamp tag, this will go ahead and do its best to backfill it",
		RunE: func(cmd *cobra.Command, args []string) error {
			return backfilleni.BackfillEni(ctx, v.GetDuration("timeout"))
		},
	}

	// TODO: Add cross-account run
	cmd.Flags().Duration("timeout", 15*time.Minute, "How long to run the backfill for")

	return cmd
}
