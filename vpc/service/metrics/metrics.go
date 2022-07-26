package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

var (
	// Gauge measures
	maxOpenConnections        = stats.Int64("db.maxOpenConnections", "Maximum number of open connections to the database", "connections")
	openConnections           = stats.Int64("db.openConnections", "The number of established connections both in use and idle", "connections")
	connectionsInUse          = stats.Int64("db.connectionsInUse", "The number of connections currently in use", "connections")
	connectionsIdle           = stats.Int64("db.connectionsIdle", "The number of idle connections", "connections")
	subnetsCount              = stats.Int64("subnets.count", "The number of rows in subnets table", stats.UnitNone)
	branchEnisCount           = stats.Int64("branch_enis.count", "The number of rows in branch_enis table", stats.UnitNone)
	assignmentsCount          = stats.Int64("assignments.count", "The number of rows in assignments table", stats.UnitNone)
	branchEniAttachmentsCount = stats.Int64("branch_eni_attachments.count", "The number of rows in branch_eni_assignments table", stats.UnitNone)
	unattachedEnisCount       = stats.Int64("unattached_enis.count", "The number of rows in branch_enis table that don't have an attachment", stats.UnitNone)

	// Counter measures
	waitCount         = stats.Int64("db.waitCount", "The total number of connections waited for", "connections")
	waitDuration      = stats.Int64("db.waitDuration", "The total time blocked waiting for a new connection", "ns")
	maxIdleClosed     = stats.Int64("db.maxIdleClosed", "The total number of connections closed due to SetMaxIdleConns", "connections")
	maxLifetimeClosed = stats.Int64("db.maxLifetimeClosed", "The total number of connections closed due to SetConnMaxLifetime", "connections")

	ErrorReconcileEIPsCount                   = stats.Int64("error.reconcileEIPs", "The number of time failing to reconcile elastic IPs", stats.UnitNone)
	ErrorReconcileAZsCount                    = stats.Int64("error.reconcileAZs", "The number of time failing to reconcile availability zones", stats.UnitNone)
	ErrorPruneLastUsedIPsCount                = stats.Int64("error.pruneLastUsedIPs", "The number of time failing to prune last used IP addreses", stats.UnitNone)
	ErrorReconcileBranchENIAttachmentsCount   = stats.Int64("error.reconcileBranchENIAttachments", "The number of time failing to reconcile branch ENI attachments", stats.UnitNone)
	ErrorGCBranchENIsCount                    = stats.Int64("error.gcBranchENIs", "The number of time failing to GC branch ENIs", stats.UnitNone)
	ErrorDeleteExcessBranchENIsCount          = stats.Int64("error.deleteExcessBranchENIs", "The number of time failing to delete excess branch ENIs", stats.UnitNone)
	ErrorDetachUnusedBranchENIsCount          = stats.Int64("error.detachUnusedBranchENIs", "The number of time failing to detach unused branch ENIs", stats.UnitNone)
	ErrorDeleteFailedAssignmentsCount         = stats.Int64("error.deleteFailedAssignments", "The number of time failing to delete failed assignments", stats.UnitNone)
	ErrorReconcileSubnetsCount                = stats.Int64("error.reconcileSubnets", "The number of time failing to reconcile subnets", stats.UnitNone)
	ErrorReconcileBranchENIsCount             = stats.Int64("error.reconcileBranchENIs", "The number of time failing to reconcile branch ENIs", stats.UnitNone)
	ErrorReconcileTrunkENIsCount              = stats.Int64("error.reconcileTrunkENIs", "The number of time failing to reconcile trunk ENIs", stats.UnitNone)
	ErrorAssociateBranchENICount              = stats.Int64("error.associateBranchENI", "The number of time failing to finish branch ENI association", stats.UnitNone)
	ErrorDisassociateBranchENICount           = stats.Int64("error.disassociateBranchENI", "The number of time failing to finish branch ENI disassociation", stats.UnitNone)
	ErrorReconcileSGsCount                    = stats.Int64("error.reconcileSGs", "The number of time failing to reconcile security groups", stats.UnitNone)
	ErrorReconcileSubnetCIDRReservationsCount = stats.Int64("error.reconcileSubnetCIDRReservations", "The number of time failing to reconcile subnet CIDR reservations", stats.UnitNone)
	ErrorMonitorRouteTableCount               = stats.Int64("error.monitorRouteTable", "The number of time failing to monitor route table", stats.UnitNone)

	// Distribution measures

	ReconcileEIPsLatency                   = stats.Int64("loop.reconcileEIPs.latency", "The latency to reconcile elastic IPs", stats.UnitMilliseconds)
	ReconcileAZsLatency                    = stats.Int64("loop.reconcileAZs.latency", "The latency to reconcile availability zones", stats.UnitMilliseconds)
	PruneLastUsedIPsLatency                = stats.Int64("loop.pruneLastUsedIPs.latency", "The latency to prune last used IPs", stats.UnitMilliseconds)
	ReconcileBranchENIAttachmentsLatency   = stats.Int64("loop.reconcileBranchENIAttachments.latency", "The latency to reconcile branch ENI attachments", stats.UnitMilliseconds)
	GCBranchENIsLatency                    = stats.Int64("loop.gcBranchENIs.latency", "The latency to GC branch ENIs", stats.UnitMilliseconds)
	DeleteExcessBranchENIsLatency          = stats.Int64("loop.deleteExcessBranchENIs.latency", "The latency to delete excess branch ENIs", stats.UnitMilliseconds)
	DetachUnusedBranchENIsLatency          = stats.Int64("loop.detachUnusedBranchENIs.latency", "The latency to detach unused branch ENIs", stats.UnitMilliseconds)
	DeleteFailedAssignmentsLatency         = stats.Int64("loop.deleteFailedAssignments.latency", "The latency to delete failed assignments", stats.UnitMilliseconds)
	ReconcileSubnetsLatency                = stats.Int64("loop.reconcileSubnets.latency", "The latency to reconcile subnets", stats.UnitMilliseconds)
	ReconcileBranchENIsLatency             = stats.Int64("loop.reconcileBranchENIs.latency", "The latency to reconcile branch ENIs", stats.UnitMilliseconds)
	ReconcileTrunkENIsLatency              = stats.Int64("loop.reconcileTrunkENIs.latency", "The latency to reconcile trunk ENIs", stats.UnitMilliseconds)
	AssociateBranchENILatency              = stats.Int64("loop.associateBranchENI.latency", "The latency to associate branch ENI", stats.UnitMilliseconds)
	DisassociateBranchENILatency           = stats.Int64("loop.disassociateBranchENI.latency", "The latency to disassociate branch ENI", stats.UnitMilliseconds)
	ReconcileSGsLatency                    = stats.Int64("loop.reconcileSGs.latency", "The latency to reconcile security groups", stats.UnitMilliseconds)
	ReconcileSubnetCIDRReservationsLatency = stats.Int64("loop.reconcileSubnetCIDRReservations.latency", "The latency to reconcile subnet CIDR reservations", stats.UnitMilliseconds)
	MonitorRouteTableLatency               = stats.Int64("loop.monitorRouteTable.latency", "The latency to monitor route table", stats.UnitMilliseconds)
)

func init() {
	gaugeMeasures := []stats.Measure{
		maxOpenConnections, openConnections, connectionsInUse, connectionsIdle,
		subnetsCount, branchEnisCount, assignmentsCount, branchEniAttachmentsCount, unattachedEnisCount,
	}
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
		ErrorReconcileEIPsCount,
		ErrorReconcileAZsCount,
		ErrorPruneLastUsedIPsCount,
		ErrorReconcileBranchENIAttachmentsCount,
		ErrorGCBranchENIsCount,
		ErrorDeleteExcessBranchENIsCount,
		ErrorDetachUnusedBranchENIsCount,
		ErrorDeleteFailedAssignmentsCount,
		ErrorReconcileSubnetsCount,
		ErrorReconcileBranchENIsCount,
		ErrorReconcileTrunkENIsCount,
		ErrorAssociateBranchENICount,
		ErrorDisassociateBranchENICount,
		ErrorReconcileSGsCount,
		ErrorReconcileSubnetCIDRReservationsCount,
		ErrorMonitorRouteTableCount,
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

	distributionMeasures := []stats.Measure{
		ReconcileEIPsLatency,
		ReconcileAZsLatency,
		PruneLastUsedIPsLatency,
		ReconcileBranchENIAttachmentsLatency,
		GCBranchENIsLatency,
		DeleteExcessBranchENIsLatency,
		DetachUnusedBranchENIsLatency,
		DeleteFailedAssignmentsLatency,
		ReconcileSubnetsLatency,
		ReconcileBranchENIsLatency,
		ReconcileTrunkENIsLatency,
		AssociateBranchENILatency,
		DisassociateBranchENILatency,
		ReconcileSGsLatency,
		ReconcileSubnetCIDRReservationsLatency,
		MonitorRouteTableLatency,
	}

	for idx := range distributionMeasures {
		if err := view.Register(
			&view.View{
				Name:        distributionMeasures[idx].Name(),
				Description: distributionMeasures[idx].Description(),
				Measure:     distributionMeasures[idx],
				Aggregation: view.Distribution(),
			},
		); err != nil {
			panic(err)
		}
	}
}

type CollectorConfig struct {
	// The interval to collect table metrics.
	// If 0, then disable collecting table metrics.
	TableMetricsInterval time.Duration
}

type Collector struct {
	db     *sql.DB
	ctx    context.Context
	config *CollectorConfig
}

func NewCollector(ctx context.Context, db *sql.DB, config *CollectorConfig) *Collector {
	return &Collector{ctx: ctx, db: db, config: config}
}

func (c *Collector) Start() {
	go c.collectDbMetrics(c.ctx)
	if c.config.TableMetricsInterval > 0 {
		go c.collectTableMetrics(c.ctx)
	}
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

func (c *Collector) collectTableMetrics(ctx context.Context) {
	ticker := time.NewTicker(c.config.TableMetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.recordTableCounts(ctx)
			c.recordUnattachedEnisCount(ctx)
		}
	}
}

func (c *Collector) recordTableCounts(ctx context.Context) {
	measureByName := map[string]*stats.Int64Measure{
		"subnets":                subnetsCount,
		"branch_enis":            branchEnisCount,
		"assignments":            assignmentsCount,
		"branch_eni_attachments": branchEniAttachmentsCount,
	}

	for table, measure := range measureByName {
		count, err := c.queryCount(ctx, "SELECT COUNT(*) FROM "+table)
		if err != nil {
			logger.G(ctx).Warnf("failed to query count of table %s: %s", table, err)
		} else {
			stats.Record(ctx, measure.M(count))
		}
	}
}

func (c *Collector) recordUnattachedEnisCount(ctx context.Context) {
	count, err := c.queryCount(ctx, "SELECT COUNT(*) from branch_enis b WHERE NOT EXISTS "+
		"(SELECT * FROM branch_eni_attachments WHERE branch_eni = b.branch_eni AND state = 'attached');")
	if err != nil {
		logger.G(ctx).Warnf("failed to query unattached enis count: %s", err)
	} else {
		stats.Record(ctx, unattachedEnisCount.M(count))
	}
}

// Run a SELECT COUNT(*) ... query in the DB
func (c *Collector) queryCount(ctx context.Context, query string) (int64, error) {
	row := c.db.QueryRowContext(ctx, query)
	if row.Err() != nil {
		return 0, errors.Wrap(row.Err(), fmt.Sprintf("failed to run query %s", query))
	}

	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, errors.Wrap(err, fmt.Sprintf("failed to get result of query %s", query))
	}
	return count, nil
}
