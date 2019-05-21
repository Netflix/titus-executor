package main

import (
	"context"

	"github.com/Netflix/titus-executor/vpc/genconf"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func genConfCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "genconf",
		Short: "Generate Mesos Agent Configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			export := v.GetBool("export")
			resourceSetsOnly := v.GetBool("resource-sets-only")
			return genconf.GenConf(ctx, iipGetter(), export, resourceSetsOnly)
		},
	}

	cmd.Flags().Bool("export", false, "Generate environment variables with export declaration")
	cmd.Flags().Bool("resource-sets-only", false, "Don't generate environment variables, just the resourceset declaration")

	return cmd
}
