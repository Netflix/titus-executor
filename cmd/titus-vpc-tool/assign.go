package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Netflix/titus-executor/vpc/tool/allocate"

	"github.com/Netflix/titus-executor/vpc/tool/assign2"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func assignNetworkCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assign",
		Short: "assign an IP (or set of IPs) to this interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			locker, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}

			switch strings.ToLower(v.GetString(generationFlagName)) {
			case "v1":
				return allocate.Allocate(ctx,
					iipGetter(),
					locker,
					conn,
					v.GetStringSlice("security-groups"),
					v.GetInt("device-idx"),
					v.GetBool("allocate-ipv6-address"),
					v.GetString("allocation-uuid"),
				)
			case "v2":
				return assign2.Assign(ctx,
					iipGetter(),
					locker,
					conn,
					v.GetStringSlice("security-groups"),
					v.GetInt("device-idx"),
					v.GetBool("assign-ipv6-address"),
					v.GetString("ipv4-allocation-uuid"),
				)
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}
		},
	}

	cmd.Flags().Int("device-idx", 0, "The device index to setup, 1-indexed (1 correlates to AWS device 1) -- using device index 0 not allowed")
	cmd.Flags().StringSlice("security-groups", []string{}, "Comma separated list of security groups")
	cmd.Flags().Bool("assign-ipv6-address", false, "Assign IPv6 Address for container")
	cmd.Flags().String("ipv4-allocation-uuid", "", "The UUID of the allocation")
	addSharedFlags(cmd.Flags())

	return cmd
}
