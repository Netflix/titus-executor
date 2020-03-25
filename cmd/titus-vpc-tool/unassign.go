package main

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/vpc/tool/assign3"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func unassignNetworkCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unassign",
		Short: "Unassign a V3 allocation",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}

			if g := v.GetString(generationFlagName); g != "v3" {
				return fmt.Errorf("Unassign does not support generation %q", g)
			}
			return assign3.Unassign(ctx, conn, v.GetString("task-id"))
		},
	}
	cmd.Flags().String("task-id", "", "The task ID for the allocation")

	addSharedFlags(cmd.Flags())

	return cmd
}
