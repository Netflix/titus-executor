package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Netflix/titus-executor/vpc/tool/assignccas"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/vpc/tool/assign3"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func assignNetworkCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assign",
		Short: "assign an IP (or set of IPs) to this interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			switch strings.ToLower(v.GetString(generationFlagName)) {
			case "v3":
				conn, err := getConnection(ctx, v)
				if err != nil {
					return err
				}

				return assign3.Assign(ctx,
					iipGetter(),
					conn,
					assign3.Arguments{
						SecurityGroups:     v.GetStringSlice("security-groups"),
						SubnetIds:          v.GetStringSlice("subnet-ids"),
						IPv4AllocationUUID: v.GetString("ipv4-allocation-uuid"),
						InterfaceAccount:   v.GetString(interfaceAccount),
						TaskID:             v.GetString("task-id"),
						ElasticIPPool:      v.GetString("elastic-ip-pool"),
						ElasticIPs:         v.GetStringSlice("elastic-ips"),
						Idempotent:         v.GetBool("idempotent"),
						Jumbo:              v.GetBool("jumbo"),
						Bandwidth:          v.GetUint64("bandwidth"),
						Burst:              v.GetBool("burst"),
						NetworkMode:        v.GetString("network-mode"),
					},
				)
			case generationCCAS:
				return assignccas.Assign(ctx, assignccas.Arguments{
					TaskID: v.GetString("task-id"),
				})
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}
		},
	}

	cmd.Flags().Int("device-idx", 0, "The device index to setup, 1-indexed (1 correlates to AWS device 1) -- using device index 0 not allowed")
	cmd.Flags().StringSlice("security-groups", []string{}, "Comma separated list of security groups")
	cmd.Flags().String("ipv4-allocation-uuid", "", "The UUID of the allocation")
	cmd.Flags().String(interfaceAccount, "", "The account that the interface should live in")
	cmd.Flags().String("task-id", "", "The task ID for the allocation")
	cmd.Flags().StringSlice("subnet-ids", []string{}, "The subnet IDs for the allocation")
	cmd.Flags().StringSlice("elastic-ips", []string{}, "One of the elastic IPs to use for attachment to the interface")
	cmd.Flags().String("elastic-ip-pool", "", "The elastic IP pool to allocate from")
	cmd.Flags().Bool("idempotent", false, "Try to allocate the assignment idempotently")
	cmd.Flags().Bool("jumbo", false, "Container needs jumbo frames")
	cmd.Flags().Uint64("bandwidth", 0, "Bandwidth in bps")
	cmd.Flags().Bool("burst", false, "Allow for bursting")
	cmd.Flags().String("network-mode", titus.NetworkConfiguration_UnknownNetworkMode.String(), getNetHelp())

	addSharedFlags(cmd.Flags())

	return cmd
}

func getNetHelp() string {
	modes := []string{}
	for m := range titus.NetworkConfiguration_NetworkMode_value {
		modes = append(modes, m)
	}
	return fmt.Sprintf("Network Mode, options: %s", modes)
}
