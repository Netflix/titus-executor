package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/metrics"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
)

const (
	//  Each Titus task requires an IPv4 address. Each VPC has 3 x /16s for Titus to operate in.
	// That means that the maximum number of "interesting" IPv4 rows per table are 3*(2**16) = 196608
	howManyUnusedIPsToKeep = 200000
)

func (vpcService *vpcService) pruneLastUsedIPAddresses(ctx context.Context, null data.KeyedItem, tx *sql.Tx) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "pruneLastUsedIPAddresses")
	defer span.End()

	start := time.Now()
	err := vpcService.doPruneLastUsedIPAddresses(ctx, tx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Failed to prune laste used IPs")
		stats.Record(ctx, metrics.ErrorPruneLastUsedIPsCount.M(1))
		tracehelpers.SetStatus(err, span)
		return err
	}
	stats.Record(ctx, metrics.PruneLastUsedIPsLatency.M(time.Since(start).Milliseconds()))
	return nil
}

func (vpcService *vpcService) doPruneLastUsedIPAddresses(ctx context.Context, tx *sql.Tx) (retErr error) {
	ctx, span := trace.StartSpan(ctx, "pruneLastUsedIPAddresses")
	defer span.End()

	logger.G(ctx).Debug("Beginning purge of last used ip addresses")
	result, err := tx.ExecContext(ctx,
		`WITH addresses_by_family AS
		    (SELECT id,
				last_seen,
				RANK() OVER (PARTITION BY family(ip_address), vpc_id
							 ORDER BY last_seen DESC) AS rank
		    FROM ip_last_used_v3
		    WHERE last_seen != TIMESTAMP 'EPOCH')
	    DELETE
	    FROM ip_last_used_v3
	    WHERE id IN
		    (SELECT id
		    FROM addresses_by_family
		    WHERE rank > $1 AND last_seen < now() - INTERVAL '1 DAY')`,
		howManyUnusedIPsToKeep,
	)
	if err != nil {
		err = errors.Wrap(err, "Failed to delete unused ip adddres from ip_last_used_v3s")
		tracehelpers.SetStatus(err, span)
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		err = errors.Wrap(err, "Failed to load the result from the DELETE query to ip_last_used_v3s")
		tracehelpers.SetStatus(err, span)
		return err
	}
	logger.G(ctx).WithField("deleted_ips", rows).Infof("Deleted ip addresses (left the oldest %d)", howManyUnusedIPsToKeep)
	return nil
}
