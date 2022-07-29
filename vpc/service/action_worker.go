package service

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
	"golang.org/x/time/rate"
	"k8s.io/client-go/util/workqueue"
)

type listenerEvent struct {
	listenerEvent pq.ListenerEventType
	err           error
}

// The action worker loop can be started and stopped multiple times. We need to be "safe" of that. For example,
// we can lose our leadership due to a database, or network error, and the later regain it. Flapping leadership
// in the cluster is probably indicative of something else bad though.
type actionWorker struct {
	db    *sql.DB
	dbURL string

	// The sql.tx part is useful for both use cases right now, but it might make sense to remove it in the future
	cb func(context.Context, *sql.Tx, int) error

	creationChannel string
	finishedChanel  string
	name            string
	table           string
	errorMeasure    *stats.Int64Measure
	latencyMeasure  *stats.Int64Measure

	maxWorkTime time.Duration

	pendingState string

	// Only used during testing. The reason this ready condition exists is it
	// is to let others (the test) know that the actionworker is ready to do
	// work and connected to the database.
	//
	// Since this bool is accessed by multiple goroutines, we protect it with
	// the locker in readyCond.Locker, and others can wait on it to change
	// by waiting on readyCond
	ready     bool
	readyCond *sync.Cond
}

func (actionWorker *actionWorker) loop(ctx context.Context, item data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = logger.WithField(ctx, "actionWorker", actionWorker.name)

	listenerEventCh := make(chan listenerEvent, 10)
	eventCallback := func(event pq.ListenerEventType, err error) {
		listenerEventCh <- listenerEvent{listenerEvent: event, err: err}
	}
	pqListener := pq.NewListener(actionWorker.dbURL, 500*time.Millisecond, 2*time.Minute, eventCallback)
	defer func() {
		_ = pqListener.Close()
	}()

	err := pqListener.Listen(actionWorker.creationChannel)
	if err != nil {
		return errors.Wrapf(err, "Cannot listen on %s channel", actionWorker.creationChannel)
	}
	err = pqListener.Listen(actionWorker.finishedChanel)
	if err != nil {
		return errors.Wrapf(err, "Cannot listen on %s channel", actionWorker.finishedChanel)
	}

	pingTimer := time.NewTimer(10 * time.Second)
	pingCh := make(chan error)

	wq := workqueue.NewNamedRateLimitingQueue(workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(100*time.Millisecond, time.Minute),
		// 100 qps, 100 bucket size.  This is only for retry speed and its only the overall factor (not per item)
		// wait at least 100 milliseconds before trying to work on item (assume the actual submitter of work
		// has given up).
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(100), 200)},
	), actionWorker.name)
	defer wq.ShutDown()

	errCh := make(chan error)
	go func() {
		errCh <- actionWorker.worker(ctx, wq)
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err = <-errCh:
			logger.G(ctx).WithError(err).Error("Worker failed")
			return err
		case <-pingTimer.C:
			go func() {
				pingCh <- pqListener.Ping()
			}()
		case pingErr := <-pingCh:
			if pingErr != nil {
				logger.G(ctx).WithError(pingErr).Error("Could not ping database")
			}
			pingTimer.Reset(90 * time.Second)
		case ev := <-pqListener.Notify:
			// This is a reconnect event
			if ev == nil {
				err = actionWorker.retrieveAllWorkItems(ctx, wq)
				if err != nil {
					err = errors.Wrap(err, "Could not retrieve all work items after reconnecting to postgres")
					return err
				}
			} else if ev.Channel == actionWorker.creationChannel {
				logger.G(ctx).WithField("extra", ev.Extra).Debug("Received work item")
				wq.Add(ev.Extra)
			} else if ev.Channel == actionWorker.finishedChanel {
				logger.G(ctx).WithField("extra", ev.Extra).Debug("Received work finished")
				wq.Forget(ev.Extra)
			}
		case ev := <-listenerEventCh:
			switch ev.listenerEvent {
			case pq.ListenerEventConnected:
				logger.G(ctx).Info("Connected to postgres")
				err = actionWorker.retrieveAllWorkItems(ctx, wq)
				if err != nil {
					err = errors.Wrap(err, "Could not retrieve all work items")
					return err
				}
				actionWorker.readyCond.L.Lock()
				actionWorker.ready = true
				actionWorker.readyCond.L.Unlock()
				actionWorker.readyCond.Broadcast()
				defer func() {
					actionWorker.readyCond.L.Lock()
					actionWorker.ready = false
					actionWorker.readyCond.L.Unlock()
				}()

			case pq.ListenerEventDisconnected:
				logger.G(ctx).WithError(ev.err).Error("Disconnected from postgres")
			case pq.ListenerEventReconnected:
				logger.G(ctx).Info("Reconnected to postgres")
			case pq.ListenerEventConnectionAttemptFailed:
				// Maybe this should be case for the worker bailing?
				logger.G(ctx).WithError(ev.err).Error("Failed to reconnect to postgres")
			}
		}
	}
}

func (actionWorker *actionWorker) worker(ctx context.Context, wq workqueue.RateLimitingInterface) error {
	doWorkItem := func(item interface{}) error {
		ctx, cancel := context.WithTimeout(ctx, actionWorker.maxWorkTime)
		defer cancel()
		ctx, span := trace.StartSpan(ctx, "doWorkItem")
		defer span.End()
		defer wq.Done(item)
		stringKey := item.(string)
		id, err := strconv.Atoi(stringKey)
		if err != nil {
			return errors.Wrapf(err, "Unable to parse key %q into id", stringKey)
		}

		span.AddAttributes(
			trace.Int64Attribute("id", int64(id)),
			trace.StringAttribute("actionWorker", actionWorker.name),
		)
		ctx = logger.WithField(ctx, "id", id)

		logger.G(ctx).Debug("Processing work item")
		defer logger.G(ctx).Debug("Finished processing work item")

		tx, err := actionWorker.db.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			err = errors.Wrap(err, "Could not start database transaction")
			tracehelpers.SetStatus(err, span)
			return err
		}
		defer func() {
			_ = tx.Rollback()
		}()

		_, err = tx.ExecContext(ctx, "set lock_timeout = 1000")
		if err != nil {
			err = errors.Wrap(err, "Cannot set lock timeout to 1000 milliseconds")
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error()
			return err
		}

		// Try to lock it for one second. It'll error out otherwise
		err = acquireLock(ctx, tx, actionWorker.table, id)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error()
			return err
		}

		logger.G(ctx).WithField("table", actionWorker.table).Debug("Got lock on work item")

		_, err = tx.ExecContext(ctx, "set lock_timeout = 0")
		if err != nil {
			err = errors.Wrap(err, "Cannot reset lock timeout to 0 (infinity)")
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error()
			return err
		}

		/*
		 * We intentionally return nil on the errors below, because they aren't critical to the operation of the action
		 * worker loop (for the most part). We do not want to cause these things failing to cause the entire action
		 * worker to bail.
		 */
		start := time.Now()
		err = actionWorker.cb(ctx, tx, id)
		// TODO: Consider updating the table state here
		if vpcerrors.IsPersistentError(err) {
			logger.G(ctx).WithError(err).Error("Experienced persistent error, still committing database state (assuming function updated state to failed)")
		} else if errors.Is(err, &vpcerrors.IrrecoverableError{}) {
			logger.G(ctx).WithError(err).Errorf("Experienced irrecoverable error, still committing database state (assuming function updated state to failed)")
		} else if err != nil {
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error("Failed to process item")
			stats.Record(ctx, actionWorker.errorMeasure.M(1))
			wq.AddRateLimited(item)
			return nil
		}
		stats.Record(ctx, actionWorker.latencyMeasure.M(time.Since(start).Milliseconds()))

		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Could not commit database transaction")
			tracehelpers.SetStatus(err, span)
			wq.AddRateLimited(item)
			return nil
		}

		wq.Forget(item)
		return nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		item, shuttingDown := wq.Get()
		if shuttingDown {
			return nil
		}
		err := doWorkItem(item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Received error from work function, exiting")
			return err
		}
	}
}

func (actionWorker *actionWorker) retrieveAllWorkItems(ctx context.Context, wq workqueue.RateLimitingInterface) error {
	ctx, span := trace.StartSpan(ctx, "retrieveAllWorkItems")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	span.AddAttributes(trace.StringAttribute("table", actionWorker.table))

	tx, err := actionWorker.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT id FROM %s WHERE state = $1", actionWorker.table), actionWorker.pendingState) //nolint:gosec
	if err != nil {
		err = errors.Wrap(err, "Could not query table for pending work items")
		tracehelpers.SetStatus(err, span)
		return err
	}

	for rows.Next() {
		var id int
		err = rows.Scan(&id)
		if err != nil {
			err = errors.Wrap(err, "Could not scan work item")
			tracehelpers.SetStatus(err, span)
			return err
		}
		wq.Add(strconv.Itoa(id))
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (actionWorker *actionWorker) longLivedTask() longLivedTask {
	return longLivedTask{
		workFunc:   actionWorker.loop,
		itemLister: nilItemEnumerator,
		taskName:   actionWorker.name,
	}
}
