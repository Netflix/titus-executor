package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/allocate"
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

			return allocate.AllocateNetwork(ctx,
				iipGetter(),
				locker,
				conn,
				v.GetStringSlice("security-groups"),
				v.GetInt("device-idx"),
				v.GetBool("allocate-ipv6-address"))
		},
	}

	cmd.Flags().Int("device-idx", 0, "The device index to setup, 1-indexed (1 correlates to AWS device 1) -- using device index 0 not allowed")
	cmd.Flags().StringSlice("security-groups", []string{}, "Comma separated list of security groups")
	cmd.Flags().Bool("allocate-ipv6-address", false, "Allocate IPv6 Address for container")
	addSharedFlags(cmd.Flags())

	return cmd
}
