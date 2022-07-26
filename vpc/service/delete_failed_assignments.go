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
	timeBetweenDeleteFailedAssignments = 5 * time.Minute
)

func (vpcService *vpcService) deleteFailedAssignments(ctx context.Context, protoItem data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		start := time.Now()
		err := vpcService.doDeleteFailedAssignments(ctx)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to delete failed assignments")
			stats.Record(ctx, metrics.ErrorDeleteFailedAssignmentsCount.M(1))
		} else {
			stats.Record(ctx, metrics.DeleteFailedAssignmentsLatency.M(time.Since(start).Milliseconds()))
		}
		err = waitFor(ctx, timeBetweenDeleteFailedAssignments)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doDeleteFailedAssignments(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doDeleteFailedAssignments")
	defer span.End()

	rows, err := vpcService.db.QueryContext(ctx, `
DELETE
FROM assignments
WHERE completed = 'false'
  AND created_at < now() - INTERVAL '15 minutes' RETURNING assignment_id
`)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to delete assignments from database")
		tracehelpers.SetStatus(err, span)
		return err
	}

	defer func() {
		_ = rows.Close()
	}()
	for rows.Next() {
		var assignmentID string
		err = rows.Scan(&assignmentID)
		if err != nil {
			logger.G(ctx).WithError(err).Warn("Unable to scan assignment ID")
			continue
		}
		logger.G(ctx).WithField("assignment", assignmentID).Info("Deleted failed assignment ID")
	}

	return nil
}
