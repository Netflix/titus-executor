package service

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

func (vpcService *vpcService) runScheduledTask(ctx context.Context, taskName string, interval time.Duration, cb func(context.Context, *sql.Tx) error) (retErr error) {
	ctx = logger.WithField(ctx, "taskName", taskName)
	logger.G(ctx).Info("Planning to start task")

	hostname, err := os.Hostname()
	if err != nil {
		return errors.Wrap(err, "Cannot fetch hostname")
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not start database transaction")
		return err
	}
	defer func() {
		if retErr == nil {
			retErr = tx.Commit()
			if retErr != nil {
				logger.G(ctx).WithError(err).Error("Could not commit database transaction")
			}
		} else {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.ExecContext(ctx, "INSERT INTO scheduled_tasks(name) VALUES ($1) ON CONFLICT DO NOTHING", taskName)
	if err != nil {
		return err
	}

	queryRowContext := tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(oid::int, scheduled_tasks.id) FROM scheduled_tasks, (SELECT oid FROM pg_class WHERE relname = 'scheduled_tasks') o WHERE name = $1", taskName)
	var hasLock bool
	err = queryRowContext.Scan(&hasLock)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to fetch value of pg lock")
		return err
	}

	if !hasLock {
		logger.G(ctx).Info("Skipping, as couldn't get lock")
		return nil
	}

	var lastRun time.Time
	queryRowContext = tx.QueryRowContext(ctx, "SELECT last_run FROM scheduled_tasks WHERE name = $1", taskName)
	err = queryRowContext.Scan(&lastRun)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to fetch value of last run")
		return err
	}
	if t := time.Since(lastRun); t < interval {
		logger.G(ctx).WithField("t", t).Info("Aborting task ran too recently")
		return nil
	}
	logger.G(ctx).Info("Finished task")
	_, err = tx.ExecContext(ctx, "UPDATE scheduled_tasks SET last_run = now(), hostname = $2 WHERE name = $1", taskName, hostname)
	if err != nil {
		return errors.Wrap(err, "Cannot update scheduled_tasks last_run")
	}

	return cb(ctx, tx)
}

type taskLoopWorkFunc func(context.Context, keyedItem, *sql.Tx) error

func (vpcService *vpcService) taskLoop(ctx context.Context, interval time.Duration, taskPrefix string, lister itemLister, cb taskLoopWorkFunc) error {
	ctx = logger.WithField(ctx, "taskPrefix", taskPrefix)

	t := time.NewTimer(interval / 10)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = vpcService.runTask(ctx, interval, taskPrefix, lister, cb)
			t.Reset(interval / 10)
		}
	}
}

func (vpcService *vpcService) runTask(ctx context.Context, interval time.Duration, taskPrefix string, itemLister func(ctx context.Context) ([]keyedItem, error), cb func(context.Context, keyedItem, *sql.Tx) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, taskPrefix)
	defer span.End()
	logger.G(ctx).Info("Starting task")
	items, err := itemLister(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get region / accounts")
		return err
	}
	logger.G(ctx).Info(items)
	for idx := range items {
		item := items[idx]
		taskName := fmt.Sprintf("%s_%s", taskPrefix, item.key())
		// rebind this so it doesn't get overwritten on the subsequent loop
		err := vpcService.runScheduledTask(ctx, taskName, interval, func(ctx2 context.Context, tx *sql.Tx) error {
			return cb(ctx2, item, tx)
		})
		if err != nil {
			logger.G(ctx).WithError(err).Error("Cannot run task")
		}
	}
	return nil
}

type regionAccount struct {
	accountID string
	region    string
}

func (ra *regionAccount) key() string {
	return fmt.Sprintf("%s_%s", ra.region, ra.accountID)
}

func (ra *regionAccount) String() string {
	return fmt.Sprintf("RegionAccount{region=%s account=%s}", ra.region, ra.accountID)
}
