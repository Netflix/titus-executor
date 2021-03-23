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
			netNS := []interface{}{v.GetInt("netns")}
			if v.GetString("transition-netns") != "" {
				netNS = append(netNS, v.GetString("transition-netns"))
			}
			return container2.TeardownContainer(ctx, netNS)
		},
	}

	cmd.Flags().Int("netns", 3, "The File Descriptor # of the network namespace to setup")
	cmd.Flags().String("transition-netns", "", "The name # of the network namespace to setup for transition")
	return cmd
}
