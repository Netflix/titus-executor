package service

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gotest.tools/assert"
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
