package pglock

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/pkg/errors"
)

// Lock lock
type Lock struct {
	mu     sync.RWMutex
	held   bool
	name   string
	heldBy string
	db     *sql.DB
	conn   *sql.Conn
	closed chan interface{}
	done   chan interface{}
}

// New lock
func New(name string, heldBy string, db *sql.DB) *Lock {
	return &Lock{mu: sync.RWMutex{}, name: name, heldBy: heldBy, db: db}
}

// Lock the lock
func (lock *Lock) Lock(ctx context.Context) error {
	// Start critical section -- TODO: this can be done better
	lock.mu.Lock()
	if lock.held {
		lock.mu.Unlock()
		return fmt.Errorf("lock(%v) already locked", lock.name)
	}
	lock.held = true
	lock.mu.Unlock()

	resetHeld := func() {
		lock.mu.Lock()
		lock.held = false
		lock.mu.Unlock()
	}

	conn, err := lock.db.Conn(ctx)
	lock.conn = conn
	if err != nil {
		err = errors.Wrapf(err, "could not acquire db connection for lock(%v)", lock.name)
		resetHeld()
		return err
	}

	_, err = conn.ExecContext(ctx, "INSERT INTO long_lived_locks(lock_name) VALUES ($1) ON CONFLICT (lock_name) DO NOTHING", lock.name)
	if err != nil {
		err = errors.Wrapf(err, "could not upsert lock(%v)", lock.name)
		conn.Close()
		resetHeld()
		return err
	}

	rows, err := conn.QueryContext(ctx, "SELECT pg_advisory_lock(long_lived_locks.id) FROM long_lived_locks WHERE lock_name = $1", lock.name)
	if err != nil {
		err = errors.Wrapf(err, "could not acquire advisory lock(%v)", lock.name)
		conn.Close()
		resetHeld()
		return err
	}

	hasRow := rows.Next()
	rows.Close() // close early to prevent deadlock with connection closing on error
	if !hasRow {
		err = errors.Wrapf(err, "could not acquire advisory lock(%v)", lock.name)
		conn.Close()
		resetHeld()
		return err
	}

	// If we got here, we have the lock
	res, err := conn.ExecContext(ctx, "UPDATE long_lived_locks SET held_by = $1 WHERE lock_name = $2", lock.heldBy, lock.name)
	if err != nil {
		err = errors.Wrapf(err, "could not set holder of lock(%v)", lock.name)
		lock.Unlock(ctx)
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil || affected != 1 {
		err = errors.Wrapf(err, "no rows affected when setting holder of lock(%v)", lock.name)
		lock.Unlock(ctx)
		return err
	}

	return err
}

// IsHeld returns true if lock is still held
func (lock *Lock) IsHeld(ctx context.Context) (bool, error) {
	row := lock.conn.QueryRowContext(ctx, "SELECT held_by FROM long_lived_locks WHERE lock_name = $1 AND held_by = $2", lock.name, lock.heldBy)
	holder := ""
	err := row.Scan(&holder)
	if err != nil {
		err = errors.Wrapf(err, "no longer holder of lock(%v)", lock.name)
		return false, err
	}

	return true, nil
}

// Unlock the lock
func (lock *Lock) Unlock(ctx context.Context) error {
	lock.mu.Lock()
	if !lock.held {
		lock.mu.Unlock()
		return fmt.Errorf("lock(%v) not held", lock.name)
	}
	lock.held = false
	lock.mu.Unlock()

	row := lock.conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock(long_lived_locks.id) FROM long_lived_locks WHERE lock_name = $1", lock.name)
	wasHeld := true
	_ = row.Scan(&wasHeld)
	lock.conn.Close()

	return nil
}
