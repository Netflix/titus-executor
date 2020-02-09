package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/vpc/tool/gc"

	"github.com/Netflix/titus-executor/vpc/tool/gc2"
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
			switch strings.ToLower(v.GetString(generationFlagName)) {
			case "v1":
				return gc.GC(ctx,
					v.GetDuration("timeout"),
					iipGetter(),
					locker,
					conn,
				)
			case "v2":
				return gc2.GC(ctx,
					v.GetDuration("timeout"),
					iipGetter(),
					locker,
					conn,
				)
			case "v3":
				return nil
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}

		},
	}

	cmd.Flags().Duration("timeout", 10*time.Minute, "How long to allow the GC to run for")
	addSharedFlags(cmd.Flags())

	return cmd
}
