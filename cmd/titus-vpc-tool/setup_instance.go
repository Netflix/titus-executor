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
				v.GetString(interaceSubnet),
				v.GetString(interfaceAccount))
		},
	}

	addSharedFlags(cmd.Flags())
	cmd.Flags().String(interaceSubnet, "", "subnet ID to place interfaces in")
	cmd.Flags().String(interfaceAccount, "", "account ID to place interfaces in")
	if err := v.BindEnv(interaceSubnet, "VPC_INTERFACE_SUBNET"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(interfaceAccount, "VPC_INTERFACE_ACCOUNT"); err != nil {
		panic(err)
	}
	return cmd
}
