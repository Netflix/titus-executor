package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net"
	"net/url"

	"github.com/lib/pq"

	"github.com/aws/aws-sdk-go/aws/defaults"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds/rdsutils"
	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/db"
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
			conn, err := newConnection(ctx, v)
			if err != nil {
				return err
			}
			needsMigration, err := db.NeedsMigration(ctx, conn)
			if err != nil {
				return err
			}
			if !needsMigration {
				logger.G(ctx).Info("No migration needed")
				return nil
			}
			if v.GetBool("check") {
				logger.G(ctx).Fatal("Migration needed, but check set to true")
			}

			return db.Migrate(ctx, conn)
		},
	}

	cmd.Flags().Bool("check", true, "Do not perform migration, but check if migration is neccessary")
	return cmd
}

type connectorWrapper struct {
	url    *url.URL
	region string
}

func (cw *connectorWrapper) Connect(context.Context) (driver.Conn, error) {
	// Copy the URL struct, so we don't cause concurrency problems
	rawurl := *cw.url

	authtoken, err := rdsutils.BuildAuthToken(rawurl.Host, cw.region, rawurl.User.Username(), defaults.Get().Config.Credentials)
	if err != nil {
		return nil, errors.Wrap(err, "Could not build auth token")
	}
	rawurl.User = url.UserPassword(rawurl.User.Username(), authtoken)
	return pq.Open(rawurl.String())
}

func (cw *connectorWrapper) Driver() driver.Driver {
	panic("Should not be called")
}

func newConnection(ctx context.Context, v *pkgviper.Viper) (*sql.DB, error) {
	dburl := v.GetString("dburl")
	if !v.GetBool("dbiam") {
		logger.G(ctx).WithField("url", dburl).Debug("Connecting to database via URL")
		connector, err := pq.NewConnector(dburl)
		if err != nil {
			return nil, err
		}

		return sql.OpenDB(connector), nil
	}

	rawurl, err := url.Parse(dburl)
	if err != nil {
		return nil, err
	}

	if rawurl.Port() == "" {
		rawurl.Host = net.JoinHostPort(rawurl.Host, "5432")
	}

	region := v.GetString("region")
	if region == "" {
		md := ec2metadata.New(session.Must(session.NewSession()))
		region, err = md.Region()
		if err != nil {
			return nil, errors.Wrap(err, "Unable to retrieve region from IMDS")
		}
	}

	return sql.OpenDB(&connectorWrapper{
		url:    rawurl,
		region: region,
	}), nil
}
