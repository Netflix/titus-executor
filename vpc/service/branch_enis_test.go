package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"

	"github.com/Netflix/titus-executor/api/netflix/titus"

	"github.com/pkg/errors"
	"gotest.tools/assert"
)

func TestPersistentError(t *testing.T) {
	err := errors.New("test error")
	assert.Assert(t, !vpcerrors.IsPersistentError(err))
	err2 := vpcerrors.NewPersistentError(err)
	assert.Assert(t, vpcerrors.IsPersistentError(err2))

}

func TestWrap(t *testing.T) {
	err := fmt.Errorf("This is a test: %s", "Sargun")
	err = vpcerrors.NewRetryable(err)
	assert.Assert(t, vpcerrors.IsRetryable(err))
	err = errors.Wrap(err, "Wrap 1")
	assert.Assert(t, vpcerrors.IsRetryable(err))
}

func TestBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := errors.New("base error")
	assert.Assert(t, !vpcerrors.IsSleep(err))
	assert.Assert(t, !errors.Is(err, &concurrencyError{}))
	err = &concurrencyError{err: err}

	assert.Assert(t, !vpcerrors.IsSleep(err))
	assert.Assert(t, errors.Is(err, &concurrencyError{}))
	err = vpcerrors.NewWithSleep(err)
	assert.Assert(t, vpcerrors.IsSleep(err))
	assert.Assert(t, errors.Is(err, &concurrencyError{}))
	cancel()
	assert.ErrorContains(t, backOff(ctx, err), "expired")
	assert.NilError(t, backOff(ctx, errors.New("")))
}

func TestListBranchToTrunkENIMapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NilError(t, err)
	defer db.Close()

	mock.ExpectBegin()
	columns := []string{"branch_eni", "trunk_eni"}
	rows := sqlmock.NewRows(columns).AddRow(
		"eni-branch1", "eni-trunk1",
	).AddRow(
		"eni-branch2", "eni-trunk2",
	)
	mock.ExpectQuery("SELECT branch_eni, trunk_eni FROM branch_eni_attachments WHERE state = 'attached'").WillReturnRows(rows)
	mock.ExpectCommit()

	service := vpcService{db: db}
	ctx := context.Background()

	res, err := service.ListBranchToTrunkENIMapping(ctx, &titus.GetBranchToTrunkENIMappingRequest{})
	assert.NilError(t, err)

	map1 := map[string]string{
		"eni-branch1": "eni-trunk1",
		"eni-branch2": "eni-trunk2",
	}
	expected := map1

	got := res.BranchENIMapping
	fmt.Println(expected)
	fmt.Println(got)
	assert.DeepEqual(t, expected, got)
}
