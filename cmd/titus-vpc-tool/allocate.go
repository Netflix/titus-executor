package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/tool/allocate"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func allocateNetworkCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allocate",
		Short: "allocate network command",
		RunE: func(cmd *cobra.Command, args []string) error {
			locker, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}

			return allocate.Allocate(ctx,
				iipGetter(),
				locker,
				conn,
				v.GetStringSlice("security-groups"),
				v.GetInt("device-idx"),
				v.GetBool("allocate-ipv6-address"),
				v.GetString("allocation-uuid"),
				v.GetString(interaceSubnet),
				v.GetString(interfaceAccount),
			)
		},
	}

	cmd.Flags().Int("device-idx", 0, "The device index to setup, 1-indexed (1 correlates to AWS device 1) -- using device index 0 not allowed")
	cmd.Flags().StringSlice("security-groups", []string{}, "Comma separated list of security groups")
	cmd.Flags().Bool("allocate-ipv6-address", false, "Allocate IPv6 Address for container")
	cmd.Flags().String("allocation-uuid", "", "The UUID of the allocation")
	cmd.Flags().String(interaceSubnet, "", "subnet ID to place interfaces in")
	cmd.Flags().String(interfaceAccount, "", "account ID to place interfaces in")
	if err := v.BindEnv(interaceSubnet, "VPC_INTERFACE_SUBNET"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(interfaceAccount, "VPC_INTERFACE_ACCOUNT"); err != nil {
		panic(err)
	}
	addSharedFlags(cmd.Flags())

	return cmd
}
