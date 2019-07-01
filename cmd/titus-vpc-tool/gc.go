package main

import (
	"context"
	"time"

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
			defer conn.Close()

			return gc.GC(ctx,
				v.GetDuration("timeout"),
				iipGetter(),
				locker,
				conn)
		},
	}

	cmd.Flags().Duration("timeout", 10*time.Minute, "How long to allow the GC to run for")
	addSharedFlags(cmd.Flags())

	return cmd
}
