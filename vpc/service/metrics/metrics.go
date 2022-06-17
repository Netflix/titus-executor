package metrics

import (
	"context"
	"database/sql"
	"time"

	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

var (
	// Gauge measures
	maxOpenConnections = stats.Int64("db.maxOpenConnections", "Maximum number of open connections to the database", "connections")
	openConnections    = stats.Int64("db.openConnections", "The number of established connections both in use and idle", "connections")
	connectionsInUse   = stats.Int64("db.connectionsInUse", "The number of connections currently in use", "connections")
	connectionsIdle    = stats.Int64("db.connectionsIdle", "The number of idle connections", "connections")

	// Counter measures
	waitCount               = stats.Int64("db.waitCount", "The total number of connections waited for", "connections")
	waitDuration            = stats.Int64("db.waitDuration", "The total time blocked waiting for a new connection", "ns")
	maxIdleClosed           = stats.Int64("db.maxIdleClosed", "The total number of connections closed due to SetMaxIdleConns", "connections")
	maxLifetimeClosed       = stats.Int64("db.maxLifetimeClosed", "The total number of connections closed due to SetConnMaxLifetime", "connections")
	ErrorScanBranchEniCount = stats.Int64("error.scanBranchEni", "ENIs that could not be cleaned up due to error in query", stats.UnitNone)
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

	counterMeasures := []stats.Measure{
		waitCount, waitDuration, maxIdleClosed, maxLifetimeClosed,
		ErrorScanBranchEniCount,
	}
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

type Collector struct {
	db  *sql.DB
	ctx context.Context
}

func NewCollector(ctx context.Context, db *sql.DB) *Collector {
	return &Collector{ctx: ctx, db: db}
}

func (c *Collector) Start() {
	go c.collectDbMetrics(c.ctx)
}

func (c *Collector) collectDbMetrics(ctx context.Context) {
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
			dbStats := c.db.Stats()

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
