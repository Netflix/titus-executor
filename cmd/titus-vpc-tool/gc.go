package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/vpc/tool/gc3"
	"github.com/Netflix/titus-executor/logger"
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
			switch generation := strings.ToLower(v.GetString(generationFlagName)); (generation) {
			case "v1":
				logger.G(ctx).Warnf("Generation %s does not support GC")
				return nil
			case "v3":
				return gc3.GC(ctx,
					v.GetDuration("timeout"),
					iipGetter(),
					locker,
					conn,
				)
			default:
				return fmt.Errorf("Version %q not recognized", v.GetString(generationFlagName))
			}
		},
	}

	cmd.Flags().Duration("timeout", 10*time.Minute, "How long to allow the GC to run for")
	addSharedFlags(cmd.Flags())

	return cmd
}
