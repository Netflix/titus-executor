package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Netflix/titus-executor/vpc/tool/setup2"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func setupInstanceCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup-instance",
		Short: "Setup / configure instance and prepare for service",
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := getConnection(ctx, v)
			if err != nil {
				return err
			}
			locker, err := getLocker(ctx, v)
			if err != nil {
				return err
			}
			switch strings.ToLower(v.GetString(generationFlagName)) {
			case "v3":
				return setup2.Setup(ctx,
					iipGetter(),
					locker,
					conn,
					3)
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}
		},
	}

	addSharedFlags(cmd.Flags())
	cmd.Flags().String(interfaceSubnet, "", "subnet ID to place interfaces in")
	cmd.Flags().String(interfaceAccount, "", "account ID to place interfaces in")
	if err := v.BindEnv(interfaceSubnet, "VPC_INTERFACE_SUBNET"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(interfaceAccount, "VPC_INTERFACE_ACCOUNT"); err != nil {
		panic(err)
	}
	return cmd
}
