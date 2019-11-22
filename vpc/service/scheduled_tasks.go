package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

func (vpcService *vpcService) runScheduledTask(ctx context.Context, taskName string, interval time.Duration, cb func(context.Context, *sql.Tx) error) (retErr error) {
	ctx = logger.WithField(ctx, "taskName", taskName)
	logger.G(ctx).Info("Planning to start task")
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

	_, err = tx.ExecContext(ctx, "UPDATE scheduled_tasks SET last_run = now() WHERE name = $1", taskName)
	if err != nil {
		return errors.Wrap(err, "Cannot update scheduled_tasks last_run")
	}

	return cb(ctx, tx)
}

func (vpcService *vpcService) taskLoop(ctx context.Context, interval time.Duration, taskPrefix string, cb func(context.Context, regionAccount, *sql.Tx) error) error {
	t := time.NewTimer(interval / 10)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			_ = vpcService.runTask(ctx, interval, taskPrefix, cb)
			t.Reset(interval / 10)
		}
	}
}
func (vpcService *vpcService) runTask(ctx context.Context, interval time.Duration, taskPrefix string, cb func(context.Context, regionAccount, *sql.Tx) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, taskPrefix)
	defer span.End()
	logger.G(ctx).WithField("taskPrefix", taskPrefix).Info("Starting task")
	regionAccounts, err := vpcService.getRegionAccounts(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get region / accounts")
		return err
	}
	logger.G(ctx).Info(regionAccounts)
	for _, regionAndAccount := range regionAccounts {
		taskName := fmt.Sprintf("%s_%s_%s", taskPrefix, regionAndAccount.accountID, regionAndAccount.region)
		// rebind this so it doesn't get overwritten on the subsequent loop
		regionAndAccount := regionAndAccount
		err := vpcService.runScheduledTask(ctx, taskName, interval, func(ctx context.Context, tx *sql.Tx) error {
			return cb(ctx, regionAndAccount, tx)
		})
		if err != nil {
			logger.G(ctx).WithError(err).Error("Cannot run task")
		}
	}
	return nil
}
