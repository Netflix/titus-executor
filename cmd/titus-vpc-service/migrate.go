package main

import (
	"context"
	"database/sql"
	"net"
	"net/url"
	"os"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/Netflix/titus-executor/vpc/service/db/wrapper"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
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
			_, conn, err := newConnection(ctx, v)
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

func newConnection(ctx context.Context, v *pkgviper.Viper) (string, *sql.DB, error) {
	dburl := v.GetString("dburl")

	hostname, err := os.Hostname()
	if err != nil {
		return "", nil, errors.Wrap(err, "Unable to get hostname")
	}

	rawurl, err := url.Parse(dburl)
	if err != nil {
		err = errors.Wrap(err, "Cannot parse dburl")
		return "", nil, err
	}

	if rawurl.Port() == "" {
		rawurl.Host = net.JoinHostPort(rawurl.Host, "5432")
	}

	fullDBURL := rawurl.String()

	connector, err := pq.NewConnector(fullDBURL)
	if err != nil {
		err = errors.Wrap(err, "Cannot create connector")
		return "", nil, err
	}

	db := sql.OpenDB(wrapper.NewConnectorWrapper(connector, wrapper.ConnectorWrapperConfig{
		Hostname:                        hostname,
		MaxConcurrentSerialTransactions: 10,
	}))

	db.SetMaxIdleConns(v.GetInt(maxIdleConnectionsFlagName))
	db.SetMaxOpenConns(v.GetInt(maxOpenConnectionsFlagName))

	return fullDBURL, db, nil
}
