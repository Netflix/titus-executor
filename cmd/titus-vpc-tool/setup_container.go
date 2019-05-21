package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/setup_container"

	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func setupContainercommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup-container",
		Short: "Setup networking for a particular container",
		RunE: func(cmd *cobra.Command, args []string) error {
			netns := v.GetInt("netns")
			bandwidth := v.GetInt64("bandwidth")
			burst := v.GetBool("burst")
			jumbo := v.GetBool("jumbo")
			return setup_container.SetupContainer(ctx, iipGetter(), netns, uint64(bandwidth), burst, jumbo)
		},
	}

	cmd.Flags().Int("netns", 3, "The File Descriptor # of the network namespace to setup")
	cmd.Flags().Int64("bandwidth", 128*1024*1024, "Bandwidth to allocate to the device, in bps")
	cmd.Flags().Bool("burst", false, "Allow this container to burst its network allocation")
	cmd.Flags().Bool("jumbo", false, "Allow this container to use jumbo frames")
	return cmd
}
