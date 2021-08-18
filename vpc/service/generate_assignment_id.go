package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	generateAssignmentIDTimeout = time.Second * 30
	securityGroupBlockTimeout   = 1 * time.Minute
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

	jumbo     bool
	bandwidth uint64
	ceil      uint64

	transitionAssignmentRequested bool
	ipv6NotRequested              bool
}

type assignment struct {
	assignmentName string
	assignmentID   int

	assignmentChangedSecurityGroups bool

	trunk          string
	branch         branchENI
	securityGroups []string
	subnet         *subnet
	bandwidth      uint64
	ceil           uint64
	jumbo          bool

	trunkENISession  *ec2wrapper.EC2Session
	branchENISession *ec2wrapper.EC2Session

	transitionAssignmentID int
}

func (a *assignment) String() string {
	return fmt.Sprintf("Assignment{Name:%s, ID:%d, branch:%s, assoc:%s, transitionAssignmentID: %d}", a.assignmentName, a.assignmentID, a.branch.id, a.branch.associationID, a.transitionAssignmentID)
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

	// Let's validate the security groups
	err = vpcService.validateSecurityGroups(ctx, req.branchENISession, req.subnet, req.securityGroups, &regionAccount{
		accountID: req.branchENIAccount,
		region:    req.region,
	})
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	ass := &assignment{
		trunk:            req.trunkENI,
		assignmentName:   req.assignmentID,
		securityGroups:   req.securityGroups,
		subnet:           req.subnet,
		trunkENISession:  req.trunkENISession,
		branchENISession: req.branchENISession,
		jumbo:            req.jumbo,
		bandwidth:        req.bandwidth,
		ceil:             req.ceil,
	}

	err = vpcService.populateAssignment(ctx, req, ass)
	if err != nil {
		err = errors.Wrap(err, "Could not generate assignment ID with already attached ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	span.AddAttributes(
		trace.StringAttribute("branch", ass.branch.id),
		trace.StringAttribute("securityGroups", fmt.Sprint(req.securityGroups)),
	)
	if ass.assignmentChangedSecurityGroups {
		logger.G(ctx).Debug("Changing security groups")
		err = vpcService.updateBranchENISecurityGroups(ctx, ass)
		if err != nil {
			vpcService.deleteAssignment(ctx, ass)

			err = errors.Wrap(err, "Could not update branch ENI security groups")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	return ass, nil
}

// THIS IS ONLY TO BE USED TO DELETE AN ASSIGNMENT THAT FAILED IN A PARTIAL STATE
func (vpcService *vpcService) deleteAssignment(ctx context.Context, ass *assignment) {
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not start transaction")
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = tx.ExecContext(ctx, "DELETE FROM assignments WHERE id = $1", ass.assignmentID)
	if err != nil {
		logger.G(ctx).WithError(err).Error("could not delete assignment")
		return
	}

	err = tx.Commit()
	if err != nil {
		logger.G(ctx).WithError(err).Error("could not commit transaction")
	}
}

func (vpcService *vpcService) validateSecurityGroups(ctx context.Context, session *ec2wrapper.EC2Session, s *subnet, securityGroups []string, account *regionAccount) error {
	ctx, span := trace.StartSpan(ctx, "validateSecurityGroups")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("securityGroups", fmt.Sprintf("%v", securityGroups)))
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot begin read-only transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(tx)

	missingSecurityGroups := []string{}

	// This is just easier than trying to do fancy SQL.
	for idx := range securityGroups {
		sg := securityGroups[idx]
		item := vpcService.invalidSecurityGroupCache.Get(sg)
		if item != nil && !item.Expired() {
			err = status.Errorf(codes.NotFound, "Could not find security group %s; next lookup will be attempted in %s", sg, item.TTL().String())
			tracehelpers.SetStatus(err, span)
			return err
		}

		var securityGroupsFound int
		row := tx.QueryRowContext(ctx, "SELECT count(*) FROM security_groups WHERE vpc_id = $1 AND group_id = $2", s.vpcID, securityGroups[idx])
		err = row.Scan(&securityGroupsFound)
		if err != nil {
			err = fmt.Errorf("Could not scan row: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
		if securityGroupsFound == 0 {
			missingSecurityGroups = append(missingSecurityGroups, sg)
		}
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit read-only transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if len(missingSecurityGroups) == 0 {
		return nil
	}

	foundSecurityGroups := []*ec2.SecurityGroup{}
	for idx := range missingSecurityGroups {
		sg := securityGroups[idx]
		values, err := session.DescribeSecurityGroups(ctx, ec2.DescribeSecurityGroupsInput{
			GroupIds: aws.StringSlice([]string{sg}),
		})
		if err == nil {
			if l := len(values.SecurityGroups); l != 1 {
				err = fmt.Errorf("Unexpected number of security groups returned: %d", l)
				tracehelpers.SetStatus(err, span)
				return err
			}
			foundSecurityGroups = append(foundSecurityGroups, values.SecurityGroups...)
			continue
		}

		awsErr := ec2wrapper.RetrieveEC2Error(err)
		if awsErr != nil {
			if awsErr.Code() != ec2wrapper.InvalidGroupNotFound && awsErr.Code() != ec2wrapper.InvalidGroupIDMalformed {
				// Something weird happened with the AWS call. Maybe rate limiting?
				err = fmt.Errorf("Could not describe security group %s: %w", sg, awsErr)
				tracehelpers.SetStatus(err, span)
				return err
			}
		} else {
			// This shouldn't happen, but let's be defensive against AWS API weirdness.
			err = fmt.Errorf("AWS Describe API call failed: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}

		vpcService.invalidSecurityGroupCache.Set(sg, struct{}{}, securityGroupBlockTimeout)
		err = status.Errorf(codes.NotFound, "Could not find security group %s", sg)
		tracehelpers.SetStatus(err, span)
		return err
	}

	tx, err = vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot begin transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(tx)

	for _, sg := range foundSecurityGroups {
		err = insertSecurityGroup(ctx, tx, sg, account)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		err = fmt.Errorf("Could not commit transaction to update security groups: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) updateBranchENISecurityGroups(ctx context.Context, ass *assignment) error {
	ctx, span := trace.StartSpan(ctx, "updateBranchENISecurityGroups")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot begin Tx")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT security_groups, dirty_security_groups FROM branch_enis WHERE branch_enis.branch_eni = $1
FOR NO KEY UPDATE OF branch_enis`, ass.branch.id)

	// Someone could have undirtied the security groups while we were away
	var securityGroups []string
	var dirtySecurityGroups bool
	err = row.Scan(pq.Array(&securityGroups), &dirtySecurityGroups)
	if err != nil {
		err = errors.Wrap(err, "Unable to scan branch_enis for dirty_security_groups")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if !dirtySecurityGroups {
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction")
			tracehelpers.SetStatus(err, span)
			return err
		}
		return nil
	}

	_, err = ass.branchENISession.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(ass.branch.id),
		Groups:             aws.StringSlice(ass.securityGroups),
	})
	if err != nil {
		_ = tx.Rollback()
		return ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET dirty_security_groups = false,  aws_security_groups_updated = transaction_timestamp() WHERE branch_eni = $1", ass.branch.id)
	if err != nil {
		err = errors.Wrap(err, "Unable to update database to set security groups to non-dirty")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrapf(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) populateAssignment(ctx context.Context, req getENIRequest, ass *assignment) error {
	ctx, span := trace.StartSpan(ctx, "populateAssignment")
	defer span.End()

	var slowTx, fastTx *sql.Tx
	var err error
	var trunkLock *eniLockWrapper

	span.AddAttributes(trace.StringAttribute("trunk", ass.trunk))
	// Don't include getting the trunk tracker lock as part of our internal generate assignment ID timeout
	unlock, err := vpcService.trunkTracker.acquire(ctx, ass.trunk)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer unlock()

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
		return err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(slowTx)

	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Unable to begin serializable transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	err = populateAssignmentUsingAlreadyAttachedENI(ctx, req, ass, fastTx)
	if isSerializationFailure(err) || vpcerrors.IsRetryable(err) || isConcurrencyError(err) {
		_ = fastTx.Rollback()
		err2 := backOff(ctx, err)
		if err2 != nil {
			err = multierror.Append(err, err2).ErrorOrNil()
			tracehelpers.SetStatus(err, span)
			return err
		}
		goto retry
	}

	if errors.Is(err, &methodNotPossible{}) {
		logger.G(ctx).WithError(err).Warning("Got method not possible error from populateAssignmentUsingAlreadyAttachedENI, trying to get ENI and attach")
		// getENIAndAttach consumes fastTx
		err2 := vpcService.getENIAndAttach(ctx, req, ass, fastTx, slowTx, trunkLock)
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
				return err
			}
			goto retry
		}
		err2 = errors.Wrap(err2, "Could not get ENI and attach")
		tracehelpers.SetStatus(err2, span)
		return err2
	}

	if err != nil {
		err = errors.Wrap(err, "Could not get assignment using already attached ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = fastTx.Commit()
	if isSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Could not commit fastTx")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func backOff(ctx context.Context, err error) error {
	if !vpcerrors.IsSleep(err) {
		return nil
	}
	ctx, span := trace.StartSpan(ctx, "backOff")
	const minSleep = 100 * time.Millisecond
	const maxSleep = 200 * time.Millisecond
	sleep := time.Duration(rand.Int63n((maxSleep - minSleep).Nanoseconds())) + minSleep // nolint: gosec
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

func populateAssignmentUsingAlreadyAttachedENI(ctx context.Context, req getENIRequest, ass *assignment, fastTx *sql.Tx) error {
	ctx, span := trace.StartSpan(ctx, "populateAssignmentUsingAlreadyAttachedENI")
	defer span.End()

	prefixedRequired := 1
	if req.ipv6NotRequested {
		prefixedRequired = 0
	}
	span.AddAttributes(trace.BoolAttribute("prefixRequired", !req.ipv6NotRequested))
	row := fastTx.QueryRowContext(ctx, `
SELECT valid_branch_enis.id,
       valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.az,
       valid_branch_enis.account_id,
       valid_branch_enis.idx,
       valid_branch_enis.dirty_security_groups
FROM
  (SELECT branch_enis.id,
          branch_enis.branch_eni,
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
     AND (SELECT count(*) FROM subnet_usable_prefix WHERE subnet_usable_prefix.branch_eni_id = branch_enis.id) >= $4
     AND state = 'attached') valid_branch_enis
WHERE c < $5
ORDER BY c DESC, branch_eni_attached_at ASC
LIMIT 1`, ass.subnet.subnetID, ass.trunk, pq.Array(ass.securityGroups), prefixedRequired, req.maxIPAddresses)

	err := row.Scan(&ass.branch.intid, &ass.branch.id, &ass.branch.associationID, &ass.branch.az, &ass.branch.accountID, &ass.branch.idx, &ass.assignmentChangedSecurityGroups)
	if err == nil {
		logger.WithLogger(ctx, logger.G(ctx).WithFields(map[string]interface{}{
			"eni": ass.branch.id,
		}))
		logger.G(ctx).Info("Found shared ENI for assignment")
		return finishPopulateAssignmentUsingAlreadyAttachedENI(ctx, req, ass, fastTx)
	}

	if !errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("Cannot scan branch ENIs: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}
	logger.G(ctx).Debug("Falling back to trying to find ENI with any security groups")

	row = fastTx.QueryRowContext(ctx, `
SELECT valid_branch_enis.id,
       valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.az,
       valid_branch_enis.account_id,
       valid_branch_enis.idx
FROM
  (SELECT branch_enis.id,
          branch_enis.branch_eni,
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
     AND (SELECT count(*) FROM subnet_usable_prefix WHERE subnet_usable_prefix.branch_eni_id = branch_enis.id) >= $3
     AND state = 'attached') valid_branch_enis
WHERE c = 0
ORDER BY c DESC, branch_eni_attached_at ASC
LIMIT 1`,
		req.subnet.subnetID, req.trunkENI, prefixedRequired)
	err = row.Scan(&ass.branch.intid, &ass.branch.id, &ass.branch.associationID, &ass.branch.az, &ass.branch.accountID, &ass.branch.idx)
	if err == sql.ErrNoRows {
		err = newMethodNotPossibleError("populateAssignmentUsingAlreadyAttachedENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan branch ENIs")
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.WithLogger(ctx, logger.G(ctx).WithFields(map[string]interface{}{
		"eni": ass.branch.id,
	}))
	logger.G(ctx).Info("Found associated ENI for assignment, with different security groups")
	ass.assignmentChangedSecurityGroups = true
	_, err = fastTx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1, dirty_security_groups = true, modified_at = transaction_timestamp() WHERE branch_eni = $2", pq.Array(req.securityGroups), ass.branch.id)
	if err != nil {
		err = errors.Wrap(err, "Could not update branch ENI security groups / dirty security groups")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return finishPopulateAssignmentUsingAlreadyAttachedENI(ctx, req, ass, fastTx)
}

func finishPopulateAssignmentUsingAlreadyAttachedENI(ctx context.Context, req getENIRequest, ass *assignment, fastTx *sql.Tx) error {
	ctx, span := trace.StartSpan(ctx, "finishPopulateAssignmentUsingAlreadyAttachedENI")
	defer span.End()
	span.AddAttributes()

	span.AddAttributes(
		trace.StringAttribute("eni", ass.branch.id),
		trace.StringAttribute("associationID", ass.branch.associationID),
		trace.StringAttribute("assignmentID", req.assignmentID),
		trace.BoolAttribute("dirtySecurityGroups", ass.assignmentChangedSecurityGroups),
	)

	var tid sql.NullInt64
	if req.transitionAssignmentRequested {
		var ipv4addr sql.NullString
		transitionAssignmentName := fmt.Sprintf("t-%s", uuid.New().String())
		_, err := fastTx.ExecContext(ctx,
			"INSERT INTO assignments(branch_eni_association, assignment_id, is_transition_assignment, transition_last_used) VALUES ($1, $2, true, now()) ON CONFLICT (branch_eni_association) WHERE is_transition_assignment DO UPDATE SET transition_last_used = now()",
			ass.branch.associationID, transitionAssignmentName)
		if err != nil {
			err = errors.Wrap(err, "Cannot insert transition assignment")
			tracehelpers.SetStatus(err, span)
			return err
		}

		// This should never error because we just did an insert above that should be a noop.
		row := fastTx.QueryRowContext(ctx, "SELECT id, ipv4addr FROM assignments WHERE is_transition_assignment = true AND branch_eni_association = $1", ass.branch.associationID)
		err = row.Scan(&ass.transitionAssignmentID, &ipv4addr)
		if err != nil {
			err = errors.Wrap(err, "Cannot select ID from transition assignments")
			tracehelpers.SetStatus(err, span)
			return err
		}
		tid.Valid = true
		tid.Int64 = int64(ass.transitionAssignmentID)
	}

	// We do this "trick", where we return the values in order to allow a trigger to change the values on write time
	// for A/B tests.
	row := fastTx.QueryRowContext(ctx,
		"INSERT INTO assignments(branch_eni_association, assignment_id, jumbo, bandwidth, ceil, transition_assignment) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, jumbo, bandwidth, ceil",
		ass.branch.associationID, req.assignmentID, req.jumbo, req.bandwidth, req.ceil, tid)
	err := row.Scan(&ass.assignmentID, &req.jumbo, &req.bandwidth, &req.ceil)
	if err != nil {
		err = errors.Wrap(err, "Cannot scan row / insert into assignments")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) getENIAndAttach(ctx context.Context, req getENIRequest, ass *assignment, fastTx, slowTx *sql.Tx, trunkLock *eniLockWrapper) error {
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

func (vpcService *vpcService) attachENI(ctx context.Context, req getENIRequest, eni *branchENI, fastTx, slowTx *sql.Tx) (int, error) {
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
		err = fmt.Errorf("Solution not yet implemented to detach existing ENIs (required when switching subnets) -- (Indexes in use: %v), max index possible: %d", usedIndexes.UnsortedList(), req.maxBranchENIs)
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
func (vpcService *vpcService) getUnattachedBranchENIV3(ctx context.Context, fastTx, slowTx *sql.Tx, req getENIRequest, trunkLock *eniLockWrapper) (*branchENI, error) {
	ctx, span := trace.StartSpan(ctx, "getUnattachedBranchENIV3")
	defer span.End()

	var eni branchENI

	row := fastTx.QueryRowContext(ctx, `
SELECT branch_enis.branch_eni,
       branch_enis.az,
       branch_enis.account_id
FROM branch_enis
LEFT JOIN eni_permissions ON branch_enis.branch_eni = eni_permissions.branch_eni
WHERE branch_enis.subnet_id = $1
 -- Either the branch eni and trunk eni must be in the same account, or there must be an existing eni permission for
-- the account the trunk eni is in, or there must be no other network permissions

  AND (eni_permissions.account_id IS NULL
       OR eni_permissions.account_id = $2
       OR branch_enis.account_id = $2)
  AND
    (SELECT state
     FROM branch_eni_attachments
     WHERE branch_eni = branch_enis.branch_eni
       AND state IN ('attaching',
                     'attached',
                     'unattaching')) IS NULL
  AND (SELECT count(*) FROM subnet_usable_prefix WHERE subnet_usable_prefix.branch_eni_id = branch_enis.id) > 0
ORDER BY branch_enis.security_groups = $3::text[] DESC 
LIMIT 1`, req.subnet.subnetID, req.trunkENIAccount, pq.Array(req.securityGroups))
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
