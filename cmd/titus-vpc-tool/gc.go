package main

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/gc"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func gcCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Garbage collect unused IP addresses",
		RunE: func(cmd *cobra.Command, args []string) error {
			locker, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}

			return gc.GC(ctx,
				v.GetDuration("timeout"),
				v.GetDuration("min-idle-period"),
				iipGetter(),
				locker,
				conn)
		},
	}

	cmd.Flags().Duration("timeout", 5*time.Minute, "How long to allow the GC to run for")
	cmd.Flags().Duration("min-idle-period", vpc.DefaultMinIdlePeriod, "the minimum amount of time an IP must be idle before we consider it for GC")
	addSharedFlags(cmd.Flags())

	return cmd
}
