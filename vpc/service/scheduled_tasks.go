package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/pkg/errors"
)

func (vpcService *vpcService) runScheduledTask(ctx context.Context, taskName string, interval time.Duration, cb func(context.Context, *sql.Tx) error) (retErr error) {
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

	queryRowContext := tx.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(oid::int, scheduled_tasks.id) FROM scheduled_tasks, (SELECT oid FROM pg_class WHERE relname = 'scheduled_tasks') o WHERE name = $1", taskName)
	var hasLock bool
	err = queryRowContext.Scan(&hasLock)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to fetch value of pg lock")
		return err
	}

	if !hasLock {
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
		logger.G(ctx).WithField("t", t).Info("Aborting reconcilation, task ran too recently")
		return nil
	}

	_, err = tx.ExecContext(ctx, "UPDATE scheduled_tasks SET last_run = now() WHERE name = $1", taskName)
	if err != nil {
		return errors.Wrap(err, "Cannot update scheduled_tasks last_run")
	}

	return cb(ctx, tx)
}
