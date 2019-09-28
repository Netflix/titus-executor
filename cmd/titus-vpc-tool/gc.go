package main

import (
	"context"
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/vpc/tool/gc"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func gcCommand(ctx context.Context, v *pkgviper.Viper, iipGetter instanceIdentityProviderGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Garbage collect unused IP addresses",
		RunE: func(cmd *cobra.Command, args []string) error {
			locker, conn, err := getSharedValues(ctx, v)
			if err != nil {
				return err
			}
			defer conn.Close()

			interfacesStrSlice := v.GetStringSlice("interfaces")
			interfacesIntSlice := make([]int, len(interfacesStrSlice))
			for idx := range interfacesStrSlice {
				interfacesIntSlice[idx], err = strconv.Atoi(interfacesStrSlice[idx])
				if err != nil {
					return errors.Wrapf(err, "Cannot parse interface %s", interfacesStrSlice[idx])
				}
			}

			return gc.GC(ctx,
				interfacesIntSlice,
				v.GetDuration("timeout"),
				iipGetter(),
				locker,
				conn,
				v.GetString(interaceSubnet),
				v.GetString(interfaceAccount),
			)
		},
	}

	cmd.Flags().StringSlice("interfaces", []string{}, "Which interfaces to GC")
	cmd.Flags().Duration("timeout", 10*time.Minute, "How long to allow the GC to run for")
	cmd.Flags().String(interaceSubnet, "", "subnet ID to place interfaces in")
	cmd.Flags().String(interfaceAccount, "", "account ID to place interfaces in")
	if err := v.BindEnv(interaceSubnet, "VPC_INTERFACE_SUBNET"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(interfaceAccount, "VPC_INTERFACE_ACCOUNT"); err != nil {
		panic(err)
	}
	addSharedFlags(cmd.Flags())

	return cmd
}
