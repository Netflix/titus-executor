package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Netflix/titus-executor/vpc/tool/container2"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func setupContainercommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup-container",
		Short: "Setup networking for a particular container",
		RunE: func(cmd *cobra.Command, args []string) error {
			pid1dirfd := v.GetInt("pid-1-dir-fd")
			switch strings.ToLower(v.GetString(generationFlagName)) {
			case "v2", "v3":
				return container2.SetupContainer(ctx, iipGetter(), pid1dirfd)
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}
		},
	}

	cmd.Flags().Int("pid-1-dir", 3, "The File Descriptor # of the pid 1 directory to setup")
	cmd.Flags().String(generationFlagName, generationDefaultValue, "Generation of VPC Tool to use, specify v1, or v2")
	return cmd
}
