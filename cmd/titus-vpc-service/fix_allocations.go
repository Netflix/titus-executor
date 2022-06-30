package main

import (
	"context"

	// nolint: staticcheck
	"github.com/Netflix/titus-executor/vpc/service"
	"github.com/Netflix/titus-executor/vpc/service/config"
	"github.com/Netflix/titus-executor/vpc/service/db/wrapper"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
)

func fixAllocations(ctx context.Context, v *pkgviper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use: "fix-allocations",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, db, err := wrapper.NewConnection(ctx, v.GetString(config.DBURLFlagName), v.GetInt(config.MaxIdleConnectionsFlagName), v.GetInt(config.MaxOpenConnectionsFlagName))
			if err != nil {
				return errors.Wrap(err, "Could not connect to database")
			}

			sessionMgr := ec2wrapper.NewEC2SessionManager(v.GetString(config.WorkerRoleFlagName))

			err = service.FixOldAllocations(ctx, db, sessionMgr)
			if err != nil {
				return errors.Wrap(err, "Could not fix old allocations")
			}
			return nil
		},
	}
	return cmd

}
