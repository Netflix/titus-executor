package service

import (
	"context"
	"database/sql"

	"github.com/pkg/errors"
)

func beginSerializableTx(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		return nil, err
	}

	/* See:
	 * https://www.postgresql.org/docs/9.1/transaction-iso.html
	 * A sequential scan will always necessitate a relation-level predicate lock.
	 * This can result in an increased rate of serialization failures.
	 * It may be helpful to encourage the use of index scans by reducing random_page_cost and/or increasing cpu_tuple_cost.
	 * Be sure to weigh any decrease in transaction rollbacks and restarts against any overall change in query execution time.
	 */
	_, err = tx.ExecContext(ctx, "SET enable_seqscan = false")
	if err != nil {
		_ = tx.Rollback()
		err = errors.Wrap(err, "Cannot disable seqscan")
		return nil, err
	}

	return tx, err
}
