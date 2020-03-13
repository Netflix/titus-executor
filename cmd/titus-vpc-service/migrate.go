package main

import (
	"context"
	"database/sql"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/Netflix/titus-executor/vpc/service/db/wrapper"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	pkgviper "github.com/spf13/viper"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

var (
	maxOpenConnections = stats.Int64("db.maxOpenConnections", "Maximum number of open connections to the database", "connections")
	openConnections    = stats.Int64("db.openConnections", "The number of established connections both in use and idle", "connections")
	connectionsInUse   = stats.Int64("db.connectionsInUse", "The number of connections currently in use", "connections")
	connectionsIdle    = stats.Int64("db.connectionsIdle", "The number of idle connections", "connections")

	waitCount         = stats.Int64("db.waitCount", "The total number of connections waited for", "connections")
	waitDuration      = stats.Int64("db.waitDuration", "The total time blocked waiting for a new connection", "ns")
	maxIdleClosed     = stats.Int64("db.maxIdleClosed", "The total number of connections closed due to SetMaxIdleConns", "connections")
	maxLifetimeClosed = stats.Int64("db.maxLifetimeClosed", "The total number of connections closed due to SetConnMaxLifetime", "connections")
)

func init() {
	gaugeMeasures := []stats.Measure{maxOpenConnections, openConnections, connectionsInUse, connectionsIdle}
	for idx := range gaugeMeasures {
		if err := view.Register(
			&view.View{
				Name:        gaugeMeasures[idx].Name(),
				Description: gaugeMeasures[idx].Description(),
				Measure:     gaugeMeasures[idx],
				Aggregation: view.LastValue(),
			},
		); err != nil {
			panic(err)
		}
	}

	counterMeasures := []stats.Measure{waitCount, waitDuration, maxIdleClosed, maxLifetimeClosed}
	for idx := range counterMeasures {
		if err := view.Register(
			&view.View{
				Name:        counterMeasures[idx].Name(),
				Description: counterMeasures[idx].Description(),
				Measure:     counterMeasures[idx],
				Aggregation: view.Count(),
			},
		); err != nil {
			panic(err)
		}
	}
}

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

func collectDBMetrics(ctx context.Context, db *sql.DB) {
	var (
		lastWaitCount         int64
		lastMaxIdleClosed     int64
		lastMaxLifetimeClosed int64
		lastWaitDuration      = time.Duration(0)
	)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dbStats := db.Stats()

			incrementalWaitCount := dbStats.WaitCount - lastWaitCount
			lastWaitCount = dbStats.WaitCount
			incrementalLastWaitDuration := dbStats.WaitDuration - lastWaitDuration
			lastWaitDuration = dbStats.WaitDuration
			incrementalMaxIdleClosed := dbStats.MaxIdleClosed - lastMaxIdleClosed
			lastMaxIdleClosed = dbStats.MaxIdleClosed
			incrementalMaxLifetimeClosed := dbStats.MaxLifetimeClosed - lastMaxLifetimeClosed
			lastMaxLifetimeClosed = dbStats.MaxLifetimeClosed

			stats.Record(ctx,
				maxOpenConnections.M(int64(dbStats.MaxOpenConnections)),
				openConnections.M(int64(dbStats.OpenConnections)),
				connectionsInUse.M(int64(dbStats.InUse)),
				connectionsIdle.M(int64(dbStats.Idle)),
				waitCount.M(incrementalWaitCount),
				waitDuration.M(incrementalLastWaitDuration.Nanoseconds()),
				maxIdleClosed.M(incrementalMaxIdleClosed),
				maxLifetimeClosed.M(incrementalMaxLifetimeClosed),
			)
		}
	}
}
