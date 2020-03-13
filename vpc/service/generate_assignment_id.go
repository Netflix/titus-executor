package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sync/semaphore"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	generateAssignmentIDTimeout = time.Second * 30
)

type eniLockWrapper struct {
	sem      *semaphore.Weighted
	released bool
}

func (e *eniLockWrapper) release() {
	if e == nil {
		return
	}

	if !e.released {
		e.released = true
		e.sem.Release(1)
	}
}

type getENIRequest struct {
	region string

	trunkENI        string
	trunkENIAccount string
	trunkENISession *ec2wrapper.EC2Session

	branchENIAccount string
	branchENISession *ec2wrapper.EC2Session

	assignmentID   string
	subnet         *subnet
	securityGroups []string

	maxBranchENIs  int
	maxIPAddresses int
}

type getENIResponse struct {
	assignmentID        int
	dirtySecurityGroups bool
	eni                 *branchENI
}

type assignment struct {
	assignmentName string
	assignmentID   int
	branch         *branchENI
	securityGroups []string
	subnet         *subnet

	trunkENISession  *ec2wrapper.EC2Session
	branchENISession *ec2wrapper.EC2Session
}

func (a *assignment) String() string {
	return fmt.Sprintf("Assignment{Name:%s, ID:%d, branch:%s, assoc:%s}", a.assignmentName, a.assignmentID, a.branch.id, a.branch.associationID)
}

// TODO: Consider breaking this into its own module

// This gets an ENI to do "assignment" with
func (vpcService *vpcService) generateAssignmentID(ctx context.Context, req getENIRequest) (*assignment, error) {
	ctx, span := trace.StartSpan(ctx, "generateAssignmentID")
	defer span.End()

	ctx = logger.WithFields(ctx, map[string]interface{}{
		"trunk":            req.trunkENI,
		"trunkENIAccount":  req.trunkENIAccount,
		"branchENIAccount": req.branchENIAccount,
		"assignmentID":     req.assignmentID,
		"subnet":           req.subnet.subnetID,
	})

	span.AddAttributes(trace.StringAttribute("assignmentID", req.assignmentID))
	var err error
	var response *getENIResponse
	// fastTx = isolation level serial -- work must be done quickly (side effects not appreciated)
	// slowTx = isolation level read repeatable -- work

	/* Preload the "heavy" work */
	if req.trunkENISession == nil {
		req.trunkENISession, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: req.region, AccountID: req.trunkENIAccount})
		if err != nil {
			err = errors.Wrap(err, "Could not get trunk ENI session")
			return nil, err
		}
	}

	if req.branchENISession == nil {
		req.branchENISession, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: req.region, AccountID: req.branchENIAccount})
		if err != nil {
			err = errors.Wrap(err, "Could not get branch ENI session")
			return nil, err
		}
	}

	if req.assignmentID == "" {
		return nil, fmt.Errorf("%q is in invalid assignment ID", req.assignmentID)
	}

	sort.Strings(req.securityGroups)

	response, err = vpcService.generateAssignmentID2(ctx, &req)
	if err != nil {
		err = errors.Wrap(err, "Could not generate assignment ID with already attached ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	span.AddAttributes(
		trace.StringAttribute("branch", response.eni.id),
		trace.StringAttribute("securityGroups", fmt.Sprint(req.securityGroups)),
	)

	assignment := &assignment{
		assignmentName:   req.assignmentID,
		assignmentID:     response.assignmentID,
		branch:           response.eni,
		securityGroups:   req.securityGroups,
		subnet:           req.subnet,
		trunkENISession:  req.trunkENISession,
		branchENISession: req.branchENISession,
	}
	if !response.dirtySecurityGroups {
		return assignment, nil
	}

	slowTx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot begin Tx")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = slowTx.Rollback()
	}()

	row := slowTx.QueryRowContext(ctx, `
SELECT security_groups, dirty_security_groups FROM branch_enis WHERE branch_enis.branch_eni = $1
FOR NO KEY UPDATE OF branch_enis`, response.eni.id)

	// Someone could have undirtied the security groups while we were away
	var securityGroups []string
	var dirtySecurityGroups bool
	err = row.Scan(pq.Array(&securityGroups), &dirtySecurityGroups)
	if err != nil {
		err = errors.Wrap(err, "Unable to scan branch_enis for dirty_security_groups")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if dbSGs := sets.NewString(securityGroups...); !dbSGs.Equal(sets.NewString(req.securityGroups...)) {
		result := multierror.Append(fmt.Errorf("Security groups changed while running. DB SGs: %s, Req SGs: %s", securityGroups, req.securityGroups))
		row = slowTx.QueryRowContext(ctx, "SELECT count(*) FROM assignments WHERE assignment_id = $1", req.assignmentID)
		var count int
		err = row.Scan(&count)
		if err != nil {
			err = errors.Wrap(err, "Cannot query database for assignment")
			result = multierror.Append(result, err)
		} else if count == 0 {
			result = multierror.Append(result, errors.New("Assignment ID not found in database"))
		} else {
			_, err := slowTx.ExecContext(ctx, "DELETE FROM assignments WHERE id = $1", response.assignmentID)
			if err != nil {
				err = errors.Wrap(err, "Unable to delete assignment")
				result = multierror.Append(result, err)
			}
		}
		err = result.ErrorOrNil()
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if !dirtySecurityGroups {
		err = slowTx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		return assignment, nil
	}

	_, err = req.branchENISession.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(response.eni.id),
		Groups:             aws.StringSlice(req.securityGroups),
	})
	if err != nil {
		err = errors.Wrap(err, "Unable to modify security groups")
		tracehelpers.SetStatus(err, span)
		_, err2 := slowTx.ExecContext(ctx, "DELETE FROM assignments WHERE id = $1", response.assignmentID)
		if err2 != nil {
			err2 = errors.Wrapf(err2, "Unable to delete assignment, as modify security groups failed with: %s", err.Error())
			tracehelpers.SetStatus(err2, span)
			return nil, err2
		}
		err2 = slowTx.Commit()
		if err2 != nil {
			err2 = errors.Wrapf(err2, "Unable to perform commit, as modify security groups failed with: %s", err.Error())
			tracehelpers.SetStatus(err2, span)
			return nil, err2
		}

		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = slowTx.ExecContext(ctx, "UPDATE branch_enis SET dirty_security_groups = false WHERE branch_eni = $1", response.eni.id)
	if err != nil {
		err = errors.Wrap(err, "Unable to update database to set security groups to non-dirty")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = slowTx.Commit()
	if err != nil {
		err = errors.Wrapf(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return assignment, nil
}

func (vpcService *vpcService) generateAssignmentID2(ctx context.Context, req *getENIRequest) (*getENIResponse, error) {
	ctx, span := trace.StartSpan(ctx, "generateAssignmentID2")
	defer span.End()

	var slowTx, fastTx *sql.Tx
	var err error
	var resp *getENIResponse
	var trunkLock *eniLockWrapper

	if trunkTracker := vpcService.getTrunkTracker(req.trunkENI); trunkTracker != nil {
		now := time.Now()
		span.AddAttributes(trace.BoolAttribute("serialized", true))
		defer trunkTracker.Release()
		trunkLock = &eniLockWrapper{
			sem: trunkTracker.Value().(*semaphore.Weighted),
		}
		if err := trunkLock.sem.Acquire(ctx, 1); err != nil {
			err = errors.Wrapf(err, "Could not acquire semaphore waiting on trunk ENI: %s", req.trunkENI)
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		defer trunkLock.release()

		span.AddAttributes(trace.Int64Attribute("trunkTrackerWaitTime", time.Since(now).Nanoseconds()))
	}

	ctx, cancel := context.WithTimeout(ctx, generateAssignmentIDTimeout)
	defer cancel()

retry:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	if slowTx != nil {
		_ = slowTx.Rollback()
	}
	slowTx, err = vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Unable to start traditional transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(slowTx)

	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Unable to begin serializable transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	resp, err = getAlreadyAttachedENI(ctx, req, fastTx)
	if isSerializationFailure(err) || vpcerrors.IsRetryable(err) || isConcurrencyError(err) {
		_ = fastTx.Rollback()
		err2 := backOff(ctx, err)
		if err2 != nil {
			err = multierror.Append(err, err2).ErrorOrNil()
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		goto retry
	}

	if errors.Is(err, &methodNotPossible{}) {
		logger.G(ctx).WithError(err).Error("Got method not possible error from getAlreadyAttachedENI, trying to get ENI and attach")
		// getENIAndAttach consumes fastTx
		err2 := vpcService.getENIAndAttach(ctx, req, fastTx, slowTx, trunkLock)
		if err2 == nil {
			goto retry
		}
		if isSerializationFailure(err2) || vpcerrors.IsRetryable(err2) || errors.Is(err2, &concurrencyError{}) {
			_ = fastTx.Rollback()
			logger.G(ctx).WithError(err2).Warning("Experienced retryable error doing get eni and attach")
			err3 := backOff(ctx, err2)
			if err3 != nil {
				err = multierror.Append(err, err2, err3).ErrorOrNil()
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
			goto retry
		}
		err2 = errors.Wrap(err2, "Could not get ENI and attach")
		tracehelpers.SetStatus(err2, span)
		return nil, err2
	}

	if err != nil {
		err = errors.Wrap(err, "Could not get assignment using already attached ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = fastTx.Commit()
	if isSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Could not commit fastTx")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return resp, nil
}

func backOff(ctx context.Context, err error) error {
	if !vpcerrors.IsSleep(err) {
		return nil
	}
	ctx, span := trace.StartSpan(ctx, "backOff")
	const minSleep = 100 * time.Millisecond
	const maxSleep = 200 * time.Millisecond
	sleep := time.Duration(rand.Int63n((maxSleep - minSleep).Nanoseconds())) + minSleep
	logger.G(ctx).WithField("duration", sleep.String()).Debug("Beginning sleep")
	sleepTimer := time.NewTimer(sleep)
	defer sleepTimer.Stop()
	select {
	case <-sleepTimer.C:
	case <-ctx.Done():
		err := errors.Wrap(ctx.Err(), "Context expired while backing off")
		tracehelpers.SetStatus(err, span)
		return err
	}
	return nil
}

func getAlreadyAttachedENI(ctx context.Context, req *getENIRequest, fastTx *sql.Tx) (*getENIResponse, error) {
	ctx, span := trace.StartSpan(ctx, "getAlreadyAttachedENI")
	defer span.End()

	var eni branchENI

	row := fastTx.QueryRowContext(ctx, `
SELECT valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.az,
       valid_branch_enis.account_id,
       valid_branch_enis.idx,
       valid_branch_enis.dirty_security_groups
FROM
  (SELECT branch_enis.branch_eni,
          branch_enis.dirty_security_groups,
          branch_enis.az,
          branch_enis.account_id,
          branch_eni_attachments.idx,
          branch_eni_attachments.association_id,
          branch_eni_attachments.created_at AS branch_eni_attached_at,
     (SELECT count(*)
      FROM assignments
      WHERE assignments.branch_eni_association = branch_eni_attachments.association_id) AS c
   FROM branch_enis
   JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
   WHERE subnet_id = $1
     AND trunk_eni = $2
     AND security_groups = $3
     AND state = 'attached') valid_branch_enis
WHERE c < $4
ORDER BY c DESC, branch_eni_attached_at ASC
LIMIT 1`, req.subnet.subnetID, req.trunkENI, pq.Array(req.securityGroups), req.maxIPAddresses)

	var dirtySecurityGroups bool
	err := row.Scan(&eni.id, &eni.associationID, &eni.az, &eni.accountID, &eni.idx, &dirtySecurityGroups)
	if err == nil {
		ret := &getENIResponse{
			dirtySecurityGroups: dirtySecurityGroups,
			eni:                 &eni,
		}
		ret.assignmentID, err = insertAssignment(ctx, req, fastTx, eni)
		if err != nil {
			err = errors.Wrap(err, "Cannot insert assignment ID")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		span.SetStatus(trace.Status{
			Message: fmt.Sprintf("created assignment id %d using shared ENI %s", ret.assignmentID, eni.id),
		})
		return ret, nil
	} else if err != sql.ErrNoRows {
		err = errors.Wrap(err, "Cannot scan branch ENIs")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	row = fastTx.QueryRowContext(ctx, `
SELECT valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.az,
       valid_branch_enis.account_id,
       valid_branch_enis.idx
FROM
  (SELECT branch_enis.branch_eni,
          branch_enis.az,
          branch_enis.account_id,
          branch_eni_attachments.idx,
          branch_eni_attachments.association_id,
          branch_eni_attachments.created_at AS branch_eni_attached_at,
     (SELECT count(*)
      FROM assignments
      WHERE assignments.branch_eni_association = branch_eni_attachments.association_id) AS c
   FROM branch_enis
   JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
   WHERE subnet_id = $1
     AND trunk_eni = $2
     AND state = 'attached') valid_branch_enis
WHERE c = 0
ORDER BY c DESC, branch_eni_attached_at ASC
LIMIT 1`, req.subnet.subnetID, req.trunkENI)
	err = row.Scan(&eni.id, &eni.associationID, &eni.az, &eni.accountID, &eni.idx)
	if err == sql.ErrNoRows {
		err = newMethodNotPossibleError("getAlreadyAttachedENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot scan branch ENIs")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	_, err = fastTx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1, dirty_security_groups = true WHERE branch_eni = $2", pq.Array(req.securityGroups), eni.id)
	if err != nil {
		err = errors.Wrap(err, "Could not update branch ENI security groups / dirty security groups")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	span.AddAttributes(trace.BoolAttribute("dirtySecurityGroups", true))

	ret := &getENIResponse{
		dirtySecurityGroups: true,
		eni:                 &eni,
	}
	ret.assignmentID, err = insertAssignment(ctx, req, fastTx, eni)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert assignment ID")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	span.SetStatus(trace.Status{
		Message: fmt.Sprintf("created assignment id %d using dedicated ENI %s", ret.assignmentID, eni.id),
	})

	return ret, nil
}

func insertAssignment(ctx context.Context, req *getENIRequest, fastTx *sql.Tx, eni branchENI) (int, error) {
	ctx, span := trace.StartSpan(ctx, "insertAssignment")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("eni", eni.id),
		trace.StringAttribute("associationID", eni.associationID),
		trace.StringAttribute("assignmentID", req.assignmentID),
	)

	row := fastTx.QueryRowContext(ctx, "INSERT INTO assignments(branch_eni_association, assignment_id) VALUES ($1, $2) RETURNING id", eni.associationID, req.assignmentID)
	var id int
	err := row.Scan(&id)
	if err != nil {
		err = errors.Wrap(err, "Cannot scan row / insert into assignments")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	return id, nil
}

func (vpcService *vpcService) getENIAndAttach(ctx context.Context, req *getENIRequest, fastTx, slowTx *sql.Tx, trunkLock *eniLockWrapper) error {
	// At this point we need to attach a new ENI. This is going to be a slow procedure.
	// 0. Stop the optimistic transaction
	// 1a. Create new pessimistic txn
	// 1. Get a new ENI from the pool (or create one, we would prefer one with the right security groups)
	// We do 1b & 2a because (1) could could have created a new ENI that wouldn't be observable from 2
	// 1b. Commit pessimistic txn
	// 2a. start new optimistic txn
	// 2a. Grab the ENI
	// 2. Check if there are any ENI slots free, go to step 5
	// 3. If not start disassociating an existing ENI
	// 3b. Commit optimistic txn
	// 4a. start new pessimistic txn
	// 4. (new pessimistic txn) finish disassociating existing ENI
	// -- Someone can steal the slot from us at this point. If that happens, go back to step 3
	// 5. (new optimistic txn) start associating the ENI
	// 6. (new pessimistic txn) finish associating the ENI
	// 7. Use this for assignment
	ctx, span := trace.StartSpan(ctx, "getENIAndAttach")
	defer span.End()

	logger.G(ctx).Debug("Attaching new branch ENI")

	var err error
	var eni *branchENI
	var workItem int

	// 1
	eni, err = vpcService.getUnattachedBranchENIV3(ctx, fastTx, slowTx, req, trunkLock)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}
	logger.G(ctx).WithField("eni", eni.id).Debug("Got ENI to attach")
	// 2
	workItem, err = vpcService.attachENI(ctx, req, eni, fastTx, slowTx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to attach ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = lookupFault(ctx, afterAttachFaultKey).call(ctx)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	trunkLock.release()
	_, err = vpcService.finishAssociation(ctx, slowTx, req.trunkENISession, workItem)
	if err != nil {
		err = errors.Wrap(err, "Unable to finish association")
		logger.G(ctx).WithError(err).Error()
		tracehelpers.SetStatus(err, span)
		return err
	}
	err = slowTx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit slowTx")
		tracehelpers.SetStatus(err, span)
		return err
	}
	logger.G(ctx).Debug("Successfully associated ENI")
	return nil
}

func (vpcService *vpcService) attachENI(ctx context.Context, req *getENIRequest, eni *branchENI, fastTx, slowTx *sql.Tx) (int, error) {
	ctx, span := trace.StartSpan(ctx, "attachENI")
	defer span.End()

	var row *sql.Row
	var idx int64
	var workItem int
	var err error
	var ok bool
	var usedIndexes, availableIndexes sets.Int64
	usedIndexSlice := make([]int64, 0, req.maxBranchENIs)

	possibleIndexes := sets.NewInt64()
	for i := 1; i <= req.maxBranchENIs; i++ {
		possibleIndexes.Insert(int64(i))
	}

	row = fastTx.QueryRowContext(ctx, "SELECT count(*) FROM branch_eni_attachments WHERE state = 'attaching' AND trunk_eni = $1", req.trunkENI)
	var count int
	err = row.Scan(&count)
	if isSerializationFailure(err) {
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	if err != nil {
		err = errors.Wrap(err, "Unable to determine how many branch_eni_attachments are attaching to ENI")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	if count > 0 {
		// We could be more clever about this, like using the channel to wait for it to finish, but this should be rather seldom
		err = vpcerrors.NewWithSleep(vpcerrors.NewRetryable(fmt.Errorf("There are currently %d ongoing attachments, should sleep and retry", count)))
		logger.G(ctx).WithError(err).Debug("Returning sleepable, retryable errror")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	row = fastTx.QueryRowContext(ctx, "SELECT array_agg(idx)::int[] FROM branch_eni_attachments WHERE trunk_eni = $1 AND (state = 'attached' OR state = 'attaching' OR state = 'unattaching')", req.trunkENI)
	err = row.Scan(pq.Array(&usedIndexSlice))
	if isSerializationFailure(err) {
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	if err != nil {
		err = errors.Wrapf(err, "Unable to scan used indexes for trunk ENI %s", req.trunkENI)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	usedIndexes = sets.NewInt64(usedIndexSlice...)
	availableIndexes = possibleIndexes.Difference(usedIndexes)

	idx, ok = availableIndexes.PopAny()
	if !ok {
		err = errors.New("Solution not yet implemented to detach existing ENIs (required when switching subnets)")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	logger.G(ctx).WithFields(map[string]interface{}{
		"branch": eni.id,
		"trunk":  req.trunkENI,
		"idx":    idx,
	}).Debug("Trying to associate ENI")
	workItem, err = vpcService.startAssociation(ctx, fastTx, slowTx, eni.id, req.trunkENI, int(idx))
	if err != nil {
		err = errors.Wrap(err, "Could not start association")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	// startAssociation consumed my transaction (as it was successfull), let's go home.
	return workItem, nil
}

// This function may consume fastTx, and slowTx. Specifically, if it cannot find an ENI in the "warm pool", it will
// create an ENI, which involves discarding the fastTx, and committing the slowTx
func (vpcService *vpcService) getUnattachedBranchENIV3(ctx context.Context, fastTx, slowTx *sql.Tx, req *getENIRequest, trunkLock *eniLockWrapper) (*branchENI, error) {
	ctx, span := trace.StartSpan(ctx, "getUnattachedBranchENIV3")
	defer span.End()

	var eni branchENI

	row := fastTx.QueryRowContext(ctx, `
SELECT branch_enis.branch_eni, az, account_id  
FROM branch_enis 
WHERE 
subnet_id = $1 AND 
(SELECT state FROM branch_eni_attachments WHERE branch_eni = branch_enis.branch_eni AND state IN ('attaching', 'attached', 'unattaching')) IS NULL
ORDER BY RANDOM()
LIMIT 1`, req.subnet.subnetID)
	err := row.Scan(&eni.id, &eni.az, &eni.accountID)
	if err == nil {
		span.AddAttributes(
			trace.StringAttribute("eni", eni.id),
		)
		return &eni, nil
	} else if err != sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_ = fastTx.Rollback()
	logger.G(ctx).Warning("Could not find warm ENI, rolling back fast TX, and creating new branch ENI in slowTX")

	trunkLock.release()
	_, err = vpcService.createBranchENI(ctx, slowTx, req.branchENISession, req.subnet.subnetID, req.securityGroups)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = slowTx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit slowTx")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = vpcerrors.NewRetryable(errors.New("Had to rollback fast TX, and create ENI 'manually'"))
	tracehelpers.SetStatus(err, span)
	return nil, err
}
