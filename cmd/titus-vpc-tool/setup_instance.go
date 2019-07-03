package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/tool/setup"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func setupInstanceCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup-instance",
		Short: "Setup / configure instance and prepare for service",
		RunE: func(cmd *cobra.Command, args []string) error {
			locker, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}

			return setup.Setup(ctx,
				iipGetter(),
				locker,
				conn)
		},
	}

	addSharedFlags(cmd.Flags())

	return cmd
}
