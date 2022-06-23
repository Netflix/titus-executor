package main

import (
	"context"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/config"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/Netflix/titus-executor/vpc/service/db/wrapper"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func migrateCommand(ctx context.Context, v *pkgviper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use: "migrate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return err
			}
			_, conn, err := wrapper.NewConnection(
				ctx,
				v.GetString(config.DBURLFlagName),
				v.GetInt(config.MaxIdleConnectionsFlagName),
				v.GetInt(config.MaxOpenConnectionsFlagName))
			if err != nil {
				return err
			}

			to := v.GetUint("to")
			check := v.GetBool("check")
			if to > 0 {
				return db.MigrateTo(ctx, conn, to, check)
			}
			needsMigration, err := db.NeedsMigration(ctx, conn)
			if err != nil {
				return err
			}
			if !needsMigration {
				logger.G(ctx).Info("No migration needed")
				return nil
			}
			if check {
				logger.G(ctx).Fatal("Migration needed, but check set to true")
			}

			return db.Migrate(ctx, conn)

		},
	}

	cmd.Flags().Bool("check", true, "Do not perform migration, but check if migration is neccessary")
	cmd.Flags().Uint("to", 0, "Migrate to a specific version")
	return cmd
}
