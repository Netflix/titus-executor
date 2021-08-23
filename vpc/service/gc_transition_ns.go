package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"go.opencensus.io/trace"
)

const (
	timeBetweenGCTransitionNS = 2 * time.Minute
	minTimeTransitionNSIdle   = 5 * time.Minute
)

func (vpcService *vpcService) gcTransitionNSLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "gc_transition_ns",
		itemLister: nilItemEnumerator,
		workFunc:   vpcService.gcTransitionNSLoop,
	}
}

func (vpcService *vpcService) gcTransitionNSLoop(ctx context.Context, protoItem keyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		err := vpcService.doGCTransitionNS(ctx)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to GC transition namespaces")
		}
		err = waitFor(ctx, timeBetweenGCTransitionNS)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doGCTransitionNS(ctx context.Context) error {
	ctx, span := trace.StartSpan(ctx, "doGCTransitionNS")
	defer span.End()

	logger.G(ctx).Debug("Beginning GC of transition namespaces")
	tx, err := beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	n, err := tx.ExecContext(ctx, `
DELETE FROM assignments
WHERE is_transition_assignment
AND transition_last_used < now() - $1 * INTERVAL '1 second'
AND created_at < now() - INTERVAL '1 minute'
AND id NOT IN (SELECT transition_assignment FROM assignments)
`, minTimeTransitionNSIdle.Seconds())

	if err != nil {
		err = fmt.Errorf("Could not delete transition assignments: %w", err)
		tracehelpers.SetStatus(err, span)
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	logger.G(ctx).WithField("n", n).Info("GC'd transition assignments")
	return nil
}
