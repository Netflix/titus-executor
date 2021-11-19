package main

import (
	"context"

	mount "github.com/Netflix/titus-executor/vpc/tool/cross-mount"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

// This is a function that's never meant to be executed "externally"

func crossMountCommand(ctx context.Context, v *pkgviper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cross-mount",
		Short: "Cross mount a network namespace into a container",
		RunE: func(cmd *cobra.Command, args []string) error {
			return mount.Mount(v.GetInt("net-ns-fd"), v.GetString("where"))
		},
	}

	cmd.Flags().Int("net-ns-fd", -1, "The file descriptor of the net ns fd of the container")
	cmd.Flags().String("where", "", "Where to mount the network namespace")

	return cmd
}
