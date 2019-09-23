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
				conn,
				v.GetString("subnet"),
				v.GetString("account"))
		},
	}

	addSharedFlags(cmd.Flags())
	cmd.Flags().String("subnet", "", "subnet ID to place interfaces in")
	cmd.Flags().String("account", "", "account ID to place interfaces in")

	return cmd
}
