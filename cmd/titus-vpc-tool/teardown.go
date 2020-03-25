package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/tool/container2"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func teardownContainercommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "teardown-container",
		Short: "Tear down networking for a particular container",
		RunE: func(cmd *cobra.Command, args []string) error {
			netns := v.GetInt("netns")
			return container2.TeardownContainer(ctx, netns)
		},
	}

	cmd.Flags().Int("netns", 3, "The File Descriptor # of the network namespace to setup")
	return cmd
}
