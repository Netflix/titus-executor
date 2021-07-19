package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Netflix/titus-executor/vpc/tool/assignccas"

	"github.com/Netflix/titus-executor/vpc/tool/assign3"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func unassignNetworkCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unassign",
		Short: "Unassign a V3 allocation",
		RunE: func(cmd *cobra.Command, args []string) error {
			taskID := v.GetString("task-id")
			switch strings.ToLower(v.GetString(generationFlagName)) {
			case "v3":
				conn, err := getConnection(ctx, v)
				if err != nil {
					return err
				}

				if g := v.GetString(generationFlagName); g != "v3" {
					return fmt.Errorf("Unassign does not support generation %q", g)
				}
				return assign3.Unassign(ctx, conn, taskID)
			case generationCCAS:
				return assignccas.Unassign(ctx, taskID)
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}
		},
	}
	cmd.Flags().String("task-id", "", "The task ID for the allocation")

	addSharedFlags(cmd.Flags())

	return cmd
}
