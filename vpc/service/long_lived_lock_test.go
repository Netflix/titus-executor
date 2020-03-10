package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"
)

const (
	maxPreemption = 10 * time.Minute
)

var longLivedLockColumns = []string{"id", "lock_name", "held_by", "held_until"}

func generateLockAndRows(t *testing.T, mock sqlmock.Sqlmock) (*vpcapi.Lock, *sqlmock.Rows) {
	heldUntil := time.Now()
	protoHeldUntil, err := ptypes.TimestampProto(heldUntil)
	assert.NilError(t, err)

	rand.Seed(time.Now().UnixNano())
	lock := &vpcapi.Lock{
		Id:        rand.Int63(),
		LockName:  "branch_eni_associate_nilitem",
		HeldBy:    "titusvpcservice-cell-instance",
		HeldUntil: protoHeldUntil,
	}

	rows := sqlmock.NewRows(longLivedLockColumns).AddRow(
		lock.GetId(),
		lock.GetLockName(),
		lock.GetHeldBy(),
		heldUntil,
	)

	return lock, rows
}

func TestAPIShouldGetLocks(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	expected, rows := generateLockAndRows(t, mock)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id, lock_name, held_by, held_until FROM long_lived_locks LIMIT 1000").WillReturnRows(rows)
	mock.ExpectRollback()

	service := vpcService{db: db}

	ctx := context.Background()
	res, err := service.GetLocks(ctx, &vpcapi.GetLocksRequest{})
	assert.NilError(t, err)

	got := res.GetLocks()[0]

	assert.Assert(t, proto.Equal(expected, got))
	assert.NilError(t, mock.ExpectationsWereMet())
}

func TestAPIShouldGetLock(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	expected, rows := generateLockAndRows(t, mock)
	mock.ExpectQuery("SELECT id, lock_name, held_by, held_until FROM long_lived_locks WHERE id = \\$1").WithArgs(expected.GetId()).WillReturnRows(rows)

	service := vpcService{db: db}

	ctx := context.Background()
	got, err := service.GetLock(ctx, &vpcapi.LockId{Id: expected.GetId()})

	assert.NilError(t, err)
	assert.Assert(t, proto.Equal(expected, got))
	assert.NilError(t, mock.ExpectationsWereMet())
}

func TestAPIGetLockNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	id := int64(1)
	mock.ExpectQuery("SELECT id, lock_name, held_by, held_until FROM long_lived_locks WHERE id = \\$1").WithArgs(id).WillReturnRows(sqlmock.NewRows(longLivedLockColumns))

	service := vpcService{db: db}

	ctx := context.Background()
	_, err = service.GetLock(ctx, &vpcapi.LockId{Id: id})

	stat := status.Convert(err)
	got := stat.Code()
	expected := codes.NotFound

	assert.Equal(t, expected, got)
	assert.NilError(t, mock.ExpectationsWereMet())
}

func TestAPIShouldDeleteLock(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	service := vpcService{db: db}
	ctx := context.Background()

	id := int64(123)
	mock.ExpectExec("DELETE FROM long_lived_locks WHERE id = \\$1").WithArgs(id).WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = service.DeleteLock(ctx, &vpcapi.LockId{Id: id})

	assert.NilError(t, err)
	assert.NilError(t, mock.ExpectationsWereMet())
}

func TestAPIDeleteLockNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	id := int64(123)
	mock.ExpectExec("DELETE FROM long_lived_locks WHERE id = \\$1").WithArgs(id).WillReturnResult(sqlmock.NewResult(0, 0))

	service := vpcService{db: db}

	ctx := context.Background()
	_, err = service.DeleteLock(ctx, &vpcapi.LockId{Id: id})

	stat := status.Convert(err)
	got := stat.Code()
	expected := codes.NotFound

	assert.Equal(t, expected, got)
	assert.NilError(t, mock.ExpectationsWereMet())
}

func TestAPIShouldPreemptLock(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	service := vpcService{db: db}
	ctx := context.Background()

	lockName := "branch_eni_associate_nilitem"
	mock.ExpectExec("UPDATE long_lived_locks SET held_by = null, held_until = now\\(\\) - \\(30 \\* interval '1 sec'\\) WHERE lock_name = \\$1").WithArgs(lockName).WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = service.PreemptLock(ctx, &vpcapi.PreemptLockRequest{LockName: lockName})

	assert.NilError(t, err)
	assert.NilError(t, mock.ExpectationsWereMet())
}

func TestAPIPreemptLockNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	lockName := "branch_eni_associate_nilitem"
	mock.ExpectExec("UPDATE long_lived_locks SET held_by = null, held_until = now\\(\\) - \\(30 \\* interval '1 sec'\\) WHERE lock_name = \\$1").WithArgs(lockName).WillReturnResult(sqlmock.NewResult(0, 0))

	service := vpcService{db: db}

	ctx := context.Background()
	_, err = service.PreemptLock(ctx, &vpcapi.PreemptLockRequest{LockName: lockName})

	stat := status.Convert(err)
	got := stat.Code()
	expected := codes.NotFound

	assert.Equal(t, expected, got)
	assert.NilError(t, mock.ExpectationsWereMet())
}

// TODO: Write a proper version of tryToAcquireLock which safely preempts the lock
func (vpcService *vpcService) preemptLock(ctx context.Context, item keyedItem, llt longLivedTask) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("Deadline must be set")
	}
	if deadline.After(time.Now().Add(maxPreemption)) {
		return fmt.Errorf("Max preemption time %s exceeded", maxPreemption)
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	lockName := generateLockName(llt.taskName, item)
	var previouslyHeldBy string
	var previouslyHeldUntil, now time.Time
	row := tx.QueryRowContext(ctx, "SELECT now()")
	err = row.Scan(&now)
	if err != nil {
		err = errors.Wrap(err, "Cannot select now")
		return err
	}

	row = tx.QueryRowContext(ctx, "SELECT held_until, held_by FROM long_lived_locks WHERE lock_name = $1 FOR UPDATE", lockName)
	err = row.Scan(&previouslyHeldUntil, &previouslyHeldBy)
	if err == sql.ErrNoRows {
		previouslyHeldUntil = time.Now()
	} else if err != nil {
		err = errors.Wrap(err, "Cannot get lock held until")
		return err
	} else {
		ctx = logger.WithFields(ctx, map[string]interface{}{
			"previouslyHeldBy":    previouslyHeldBy,
			"previouslyHeldUntil": previouslyHeldUntil,
		})
	}

	timeUntilDeadline := time.Until(deadline)
	row = tx.QueryRowContext(ctx, `
INSERT INTO long_lived_locks(lock_name, held_by, held_until)
VALUES ($1, $2, now() + ($3 * interval '1 sec')) ON CONFLICT (lock_name) DO
UPDATE
SET held_by = $2,
    held_until = now() + ($3 * interval '1 sec')
RETURNING held_by, held_until, id
`, lockName, vpcService.hostname, timeUntilDeadline.Seconds())

	var id int
	var heldBy string
	var heldUntil time.Time
	err = row.Scan(&heldBy, &heldUntil, &id)
	if err != nil {
		err = errors.Wrap(err, "Unable to scan row for lock preemption query")
		return err
	}
	logger.G(ctx).WithFields(map[string]interface{}{
		"id":        id,
		"lockName":  lockName,
		"heldBy":    heldBy,
		"heldUntil": heldUntil,
	}).Info("Preempted lock")

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		return err
	}

	if previouslyHeldBy == vpcService.hostname {
		logger.G(ctx).Debug("Lock previously held by us, assuming we can use it right away")
		return nil
	}

	// This is "suboptimal" in the sense that the lock will actually be knocked out by lockTime / 4 --
	// since runUnderLock checks every lockTime / 4 if it still holds the lock
	sleepTime := previouslyHeldUntil.Sub(now)

	logger.G(ctx).WithFields(map[string]interface{}{
		"previouslyHeldUntil": previouslyHeldUntil.String(),
		"heldUntil":           heldUntil.String(),
		"now":                 now.String(),
		"sleepTimeLocation":   heldUntil.Location().String(),
		"nowLocation":         now.Location().String(),
		"sleepTime":           sleepTime.String(),
	}).Debug("sleeping to wait out previous period")
	timer := time.NewTimer(sleepTime)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
