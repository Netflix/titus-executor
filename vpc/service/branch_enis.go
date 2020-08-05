package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sync/semaphore"
)

const (
	maxAssociateTime   = 10 * time.Second
	maxDisssociateTime = 10 * time.Second
)

// eni states
const (
	attaching   = "attaching"
	attached    = "attached"
	unattaching = "unattaching"
	unattached  = "unattached"
	failed      = "failed"

	// Valid state transitions:
	// initial state: attaching - association_token is set + trunk_eni, branch_eni, and idx
	// attaching -> failed: Attachment failed in a way where it's irrecoverable
	// attaching -> attached: Successfully attached, association id is set
	// attached -> unattaching: disassocation token is set
	// unattaching -> unattached
)

func insertBranchENIIntoDB(ctx context.Context, tx *sql.Tx, iface *ec2.NetworkInterface) error {
	securityGroupIds := make([]string, len(iface.Groups))
	for idx := range iface.Groups {
		securityGroupIds[idx] = aws.StringValue(iface.Groups[idx].GroupId)
	}
	sort.Strings(securityGroupIds)

	_, err := tx.ExecContext(ctx, "INSERT INTO branch_enis (branch_eni, subnet_id, account_id, az, vpc_id, security_groups, mac, modified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, transaction_timestamp()) ON CONFLICT (branch_eni) DO NOTHING",
		aws.StringValue(iface.NetworkInterfaceId),
		aws.StringValue(iface.SubnetId),
		aws.StringValue(iface.OwnerId),
		aws.StringValue(iface.AvailabilityZone),
		aws.StringValue(iface.VpcId),
		pq.Array(securityGroupIds),
		aws.StringValue(iface.MacAddress),
	)

	return err
}

// We are given the session of the trunk ENI account
// We assume network interface permissions are already taken care of
type association struct {
	branchENI string
	trunkENI  string
}

func (vpcService *vpcService) associateNetworkInterface(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, association association, idx int) (*string, error) {
	ctx, span := trace.StartSpan(ctx, "associateNetworkInterface")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, maxAssociateTime)
	defer cancel()

	branchENI := association.branchENI
	trunkENI := association.trunkENI
	span.AddAttributes(
		trace.StringAttribute("branch", branchENI),
		trace.StringAttribute("trunk", trunkENI),
		trace.Int64Attribute("idx", int64(idx)))

	var id int
	var err error
	var pqErr *pq.Error

startAssociation:
	id, err = vpcService.startAssociation(ctx, nil, tx, branchENI, trunkENI, idx)
	if isSerializationFailure(err) {
		logger.G(ctx).WithError(pqErr).Debug("Retrying transaction")
		goto startAssociation
	}

	if err != nil {
		err = errors.Wrap(err, "Unable to start association")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = lookupFault(ctx, associateFaultKey).call(ctx)
	if err != nil {
		return nil, err
	}

	associationID, err := vpcService.finishAssociation(ctx, tx, session, id)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to finish association")
		err = errors.Wrap(err, "Unable to finish association")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return associationID, nil
}

type finishAssociationAWS struct {
	branchENIAccountID string
	region             string
	trunkENIAccountID  string
	branch             string
	trunk              string
	idx                int

	token string
}

func (vpcService *vpcService) finishAssociationAWS(ctx context.Context, slowTx *sql.Tx, session *ec2wrapper.EC2Session, args *finishAssociationAWS) (*string, error) {
	ctx, span := trace.StartSpan(ctx, "finishAssociationAWS")
	defer span.End()

	branchENISession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: args.branchENIAccountID, Region: args.region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get session for branch ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = vpcService.ensureBranchENIPermissionV3(ctx, slowTx, args.trunkENIAccountID, branchENISession, &branchENI{
		accountID: args.branchENIAccountID,
		id:        args.branch,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot ensure permission to attach branch ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if session == nil {
		session, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: args.trunkENIAccountID, Region: args.region})
		if err != nil {
			err = errors.Wrap(err, "Could not get session")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	output, err := session.AssociateTrunkInterface(ctx, ec2.AssociateTrunkInterfaceInput{
		TrunkInterfaceId:  aws.String(args.trunk),
		BranchInterfaceId: aws.String(args.branch),
		ClientToken:       aws.String(args.token),
		VlanId:            aws.Int64(int64(args.idx)),
	})

	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to associate trunk network interface")
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	return output.InterfaceAssociation.AssociationId, nil
}

func (vpcService *vpcService) finishAssociation(ctx context.Context, slowTx *sql.Tx, session *ec2wrapper.EC2Session, id int) (*string, error) {
	ctx, span := trace.StartSpan(ctx, "finishAssociation")
	defer span.End()

	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	err := acquireLock(ctx, slowTx, "branch_eni_attachments", id)
	if err != nil {
		err = errors.Wrap(err, "Failed to acquire lock")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	row := slowTx.QueryRowContext(ctx, `
SELECT branch_eni_attachments.association_token,
       branch_eni_attachments.association_id,
       branch_eni_attachments.trunk_eni,
       branch_eni_attachments.idx,
       branch_eni_attachments.error_code,
       branch_eni_attachments.error_message,
       branch_eni_attachments.state,
       trunk_enis.account_id,
       trunk_enis.region,
       branch_enis.branch_eni,
       branch_enis.account_id
FROM branch_eni_attachments
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE branch_eni_attachments.id = $1
`, id)

	var associationID, errorCode, errorMessage sql.NullString
	var token, trunk, accountID, region, state, branch, branchENIAccountID string
	var idx int

	err = row.Scan(&token, &associationID, &trunk, &idx, &errorCode, &errorMessage, &state, &accountID, &region,
		&branch, &branchENIAccountID)
	if err == sql.ErrNoRows {
		err = &irrecoverableError{err: fmt.Errorf("Work item %d not found", id)}
		tracehelpers.SetStatus(err, span)
		return nil, err
	} else if err != nil {
		err = errors.Wrap(err, "Cannot scan attachment")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	// No one else can start a new ID generation while this is running because we don't attach an ENI when
	// other ENIs are in the attaching state. So, we "best effort" lock
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		trunkTracker := vpcService.getTrunkTracker(trunk)
		if trunkTracker != nil {
			sem := trunkTracker.Value().(*semaphore.Weighted)
			e := sem.Acquire(ctx, 1)
			if e == nil {
				<-doneCh
				sem.Release(1)
			}
		}
	}()

	span.AddAttributes(trace.StringAttribute("branch", branch), trace.StringAttribute("trunk", trunk))

	switch state {
	case attached:
		if associationID.Valid {
			return &associationID.String, nil
		}
		err = errors.New("State is completed, but associationID is null")
		tracehelpers.SetStatus(err, span)
		return nil, err
	case failed:
		if !errorCode.Valid {
			err = errors.New("state of association failed, but errorCode is null")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		if !errorMessage.Valid {
			err = errors.New("state of association failed, but errorMessage is null")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		err = fmt.Errorf("Request failed with code: %q, message: %q", errorCode.String, errorMessage.String)
		tracehelpers.SetStatus(err, span)
		return nil, err
	case unattaching, unattached:
		err = fmt.Errorf("state is %s, cannot make progress in finishAssocation", state)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	assoc, err := vpcService.finishAssociationAWS(ctx, slowTx, session, &finishAssociationAWS{
		branchENIAccountID: branchENIAccountID,
		region:             region,
		trunkENIAccountID:  accountID,
		branch:             branch,
		trunk:              trunk,
		idx:                idx,
		token:              token,
	})
	if vpcerrors.IsRetryable(err) {
		err = errors.Wrap(err, "Could not associate interface to AWS, temporary error")
		tracehelpers.SetStatus(err, span)
		return nil, err
	} else if vpcerrors.IsPersistentError(err) {
		ctx, span := trace.StartSpan(ctx, "finishAssociationPersistentError")
		defer span.End()

		err = errors.Wrap(err, "Could not associate interface to AWS, unknown error")
		logger.G(ctx).WithError(err).Error("Unable to associate trunk network interface due to underlying AWS issue")

		var databaseError error
		var fastTx *sql.Tx
		var result sql.Result
		var n int64
		awsErr := ec2wrapper.RetrieveEC2Error(err)

	insertFailure:
		if fastTx != nil {
			_ = fastTx.Rollback()
		}
		fastTx, databaseError = beginSerializableTx(ctx, vpcService.db)
		defer func(tx *sql.Tx) {
			_ = tx.Rollback()
		}(fastTx)

		if databaseError != nil {
			databaseError = errors.Wrap(databaseError, "Cannot start database transaction")
			tracehelpers.SetStatus(databaseError, span)
			return nil, databaseError
		}

		if awsErr != nil {
			result, databaseError = fastTx.ExecContext(ctx,
				"UPDATE branch_eni_attachments SET state = 'failed', attachment_completed_by = $1, attachment_completed_at = now(), error_code = $2, error_message = $3  WHERE id = $4 AND state = $5",
				vpcService.hostname, awsErr.Code(), awsErr.Message(), id, state)
		} else {
			result, databaseError = fastTx.ExecContext(ctx,
				"UPDATE branch_eni_attachments SET state = 'failed', attachment_completed_by = $1, attachment_completed_at = now(), error_code = $2, error_message = $3  WHERE id = $4 AND state = $5",
				vpcService.hostname, "Unknown", err.Error(), id, state)
		}
		if isSerializationFailure(databaseError) {
			goto insertFailure
		}
		if databaseError != nil {
			databaseError = errors.Wrap(databaseError, "Unable to update branch_eni_attachments table to mark action as failed")
			logger.G(ctx).WithError(databaseError).Error()
			tracehelpers.SetStatus(databaseError, span)
			return nil, databaseError
		}

		n, databaseError = result.RowsAffected()
		if databaseError != nil {
			databaseError = errors.Wrap(databaseError, "Could not fetch rows affected from the database")
			logger.G(ctx).WithError(databaseError).Error()
			tracehelpers.SetStatus(databaseError, span)
			return nil, databaseError
		}

		if n != 1 {
			databaseError = vpcerrors.NewRetryable(fmt.Errorf("Unexpected number of database rows set to failed: %d", n))
			logger.G(ctx).WithError(databaseError).Error()
			tracehelpers.SetStatus(databaseError, span)
			return nil, databaseError
		}

		databaseError = fastTx.Commit()
		if isSerializationFailure(databaseError) {
			goto insertFailure
		}
		if databaseError != nil {
			databaseError = errors.Wrap(databaseError, "Unable to commit update to branch_eni_attachments table to mark action as failed")
			logger.G(ctx).WithError(databaseError).Error()
			tracehelpers.SetStatus(databaseError, span)
			return nil, databaseError
		}
		tracehelpers.SetStatus(err, span)
		return nil, err
	} else if err != nil {
		err = errors.Wrap(err, "Unexpected error trying to create association")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = vpcService.finishAssociationInDB(ctx, assoc, id, state)
	if err != nil {
		err = errors.Wrap(err, "Could not store finished association in the database")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return assoc, nil
}

func (vpcService *vpcService) finishAssociationInDB(ctx context.Context, assoc *string, id int, state string) error {
	ctx, span := trace.StartSpan(ctx, "finishAssociationInDB")
	defer span.End()
	var fastTx *sql.Tx
	var result sql.Result
	var n, serializationFailures int64
	var err error
retry_update:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Unable to start serialized transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	_, err = fastTx.ExecContext(ctx, "SELECT pg_notify('branch_eni_attachments_finished', $1)", strconv.Itoa(id))
	if isSerializationFailure(err) {
		serializationFailures++
		goto retry_update
	}
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_attachments_finished")
		tracehelpers.SetStatus(err, span)
		return err
	}

	result, err = fastTx.ExecContext(ctx,
		"UPDATE branch_eni_attachments SET state = 'attached', attachment_completed_by = $1, attachment_completed_at = now(), association_id = $2 WHERE id = $3 AND state = $4",
		vpcService.hostname, aws.StringValue(assoc), id, state)
	if isSerializationFailure(err) {
		serializationFailures++
		goto retry_update
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch_eni_actions table to mark state as attached")
		tracehelpers.SetStatus(err, span)
		return err
	}

	n, err = result.RowsAffected()
	if err != nil {
		err = errors.Wrap(err, "Could not fetch rows affected")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if n != 1 {
		err = vpcerrors.NewRetryable(fmt.Errorf("Unexpected number of database rows set to attached: %d", n))
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = fastTx.Commit()
	if isSerializationFailure(err) {
		serializationFailures++
		goto retry_update
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to commit change to branch_eni_attachments")
		tracehelpers.SetStatus(err, span)
		return err
	}

	span.AddAttributes(trace.Int64Attribute("serializationFailures", serializationFailures))

	return nil
}

// If slowTX is passed to this function, it is assumed that it will be used to call finishAssociate, and therefore a lock
// will be taken on the work item

// This function consumes fastTx (commits it) if successful
func (vpcService *vpcService) startAssociation(ctx context.Context, fastTx, slowTx *sql.Tx, branchENI, trunkENI string, idx int) (int, error) {
	ctx, span := trace.StartSpan(ctx, "startAssociation")
	defer span.End()

	ctx = logger.WithFields(ctx, map[string]interface{}{
		"branchENI": branchENI,
		"trunkENI":  trunkENI,
		"idx":       idx,
	})

	span.AddAttributes(
		trace.StringAttribute("branch", branchENI),
		trace.StringAttribute("trunk", trunkENI),
		trace.Int64Attribute("idx", int64(idx)),
	)

	var err error
	clientToken := uuid.New().String()
	logger.G(ctx).WithFields(map[string]interface{}{
		"fastTx":      fastTx,
		"branchENI":   branchENI,
		"trunkENI":    trunkENI,
		"idx":         idx,
		"clientToken": clientToken,
		"hostname":    vpcService.hostname,
	}).Debug()
	row := fastTx.QueryRowContext(ctx, `
INSERT INTO branch_eni_attachments(branch_eni, trunk_eni, idx, association_token, attachment_created_by, attachment_created_at, state)
VALUES ($1, $2, $3, $4, $5, now(), 'attaching') RETURNING id
`, branchENI, trunkENI, idx, clientToken, vpcService.hostname)
	var id int
	err = row.Scan(&id)
	pqErr := pqError(err)
	if pqErr != nil && pqErr.Code.Name() == "unique_violation" && (pqErr.Constraint == "branch_eni_attachments_branch_eni_trunk_eni_idx_uindex" || pqErr.Constraint == "branch_eni_attachments_trunk_eni_idx_uindex" || pqErr.Constraint == "branch_eni_attachments_branch_eni_uindex") {
		err = vpcerrors.NewWithSleep(newConcurrencyError(pqErr))
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to insert and scan into branch_eni_attachments")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	_, err = fastTx.ExecContext(ctx, "SELECT pg_notify('branch_eni_attachments_created', $1)", strconv.Itoa(id))
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_attachments_created")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	errCh := make(chan error, 1)
	if slowTx != nil {
		go func() {
			defer close(errCh)
			err = acquireLock(ctx, slowTx, "branch_eni_attachments", id)
			if err != nil {
				err = errors.Wrap(err, "Could not acquire advisory lock")
				errCh <- err
			}
		}()
	}

	err = fastTx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	select {
	case err = <-errCh:
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
	case <-ctx.Done():
		tracehelpers.SetStatus(ctx.Err(), span)
		return 0, err
	}

	logger.G(ctx).Debug("Finished starting association")

	return id, nil
}

func (vpcService *vpcService) ensureBranchENIPermissionV3(ctx context.Context, tx *sql.Tx, trunkENIAccountID string, branchENISession *ec2wrapper.EC2Session, eni *branchENI) error {
	ctx, span := trace.StartSpan(ctx, "ensureBranchENIPermissionV3")
	defer span.End()

	if eni.accountID == trunkENIAccountID {
		return nil
	}

	// This could be collapsed into a join on the above query, but for now, we wont do that
	row := tx.QueryRowContext(ctx, "SELECT COALESCE(count(*), 0) FROM eni_permissions WHERE branch_eni = $1 AND account_id = $2", eni.id, trunkENIAccountID)
	var permissions int
	err := row.Scan(&permissions)
	if err != nil {
		err = errors.Wrap(err, "Cannot retrieve from branch ENI permissions")
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	if permissions > 0 {
		return nil
	}

	logger.G(ctx).Debugf("Creating network interface permission to allow account %s to attach branch ENI in account %s", trunkENIAccountID, eni.accountID)
	ec2client := ec2.New(branchENISession.Session)
	_, err = ec2client.CreateNetworkInterfacePermissionWithContext(ctx, &ec2.CreateNetworkInterfacePermissionInput{
		AwsAccountId:       aws.String(trunkENIAccountID),
		NetworkInterfaceId: aws.String(eni.id),
		Permission:         aws.String("INSTANCE-ATTACH"),
	})

	if err != nil {
		err = errors.Wrap(err, "Cannot create network interface permission")
		return ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO eni_permissions(branch_eni, account_id) VALUES ($1, $2) ON CONFLICT DO NOTHING ", eni.id, trunkENIAccountID)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert network interface permission into database")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}

func (vpcService *vpcService) disassociateNetworkInterface(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, associationID string, force bool) error {
	ctx, span := trace.StartSpan(ctx, "disassociateNetworkInterface")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, maxDisssociateTime)
	defer cancel()

	span.AddAttributes(trace.StringAttribute("associationID", associationID))

	var id int
	var err error

	id, err = vpcService.startDissociation(ctx, tx, associationID, force)
	if err != nil {
		err = errors.Wrap(err, "Unable to start disassociation")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = lookupFault(ctx, disassociateFaultKey).call(ctx)
	if err != nil {
		return err
	}

	logger.G(ctx).WithField("id", id).Debug("Finishing disassociation")
	err = vpcService.finishDisassociation(ctx, tx, session, id)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to finish disassociation")
		err = errors.Wrap(err, "Unable to finish disassociation")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) startDissociation(ctx context.Context, slowTx *sql.Tx, associationID string, force bool) (int, error) {
	ctx, span := trace.StartSpan(ctx, "startDissociation")
	defer span.End()

	ctx = logger.WithFields(ctx, map[string]interface{}{
		"associationID": associationID,
		"force":         force,
	})

	span.AddAttributes(
		trace.StringAttribute("associationID", associationID),
		trace.BoolAttribute("force", force),
	)

	var fastTx *sql.Tx
	var row *sql.Row
	var err error
	var id int
	var state, trunk, branch string
retry:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	row = fastTx.QueryRowContext(ctx, "SELECT id, state, trunk_eni, branch_eni FROM branch_eni_attachments WHERE association_id = $1", associationID)
	err = row.Scan(&id, &state, &trunk, &branch)
	if isSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Could not query branch_eni_actions_disassociate for existing requests to disassociate")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	span.AddAttributes(
		trace.StringAttribute("branch", branch),
		trace.StringAttribute("trunk", trunk),
	)

	if state == unattaching {
		logger.G(ctx).Debug("Disassociation already in progress")
		err = fastTx.Commit()
		if isSerializationFailure(err) {
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		err = acquireLock(ctx, slowTx, "branch_eni_attachments", id)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		return id, nil
	}

	if state == unattached {
		logger.G(ctx).Debug("Disassociation already complete")
		err = fastTx.Commit()
		if isSerializationFailure(err) {
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		return id, nil
	}

	if !force {
		err = hasAssignments(ctx, fastTx, associationID)
		if isSerializationFailure(err) {
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Unable to determine if association has assignments")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
	}

	clientToken := uuid.New().String()
	_, err = fastTx.ExecContext(ctx,
		`
UPDATE branch_eni_attachments
SET state = 'unattaching',
    disassociation_token = $1,
    unattachment_created_by = $2,
    force = $3,
    unattachment_created_at = now(),
    unattachment_completed_by = NULL,
    unattachment_completed_at = NULL,
    error_code = NULL,
    error_message = NULL
WHERE association_id = $4`, clientToken, vpcService.hostname, force, associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch eni attachments to set status to unattaching")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	_, err = fastTx.ExecContext(ctx, "SELECT pg_notify('branch_eni_unattachments_created', $1)", strconv.Itoa(id))
	if isSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to notify of branch_eni_unattachments_created")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	err = fastTx.Commit()
	if isSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	err = acquireLock(ctx, slowTx, "branch_eni_attachments", id)
	if err != nil {
		err = errors.Wrap(err, "Unable to acquire lock in branch_eni_attachments")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	logger.G(ctx).WithFields(map[string]interface{}{
		"associationID": associationID,
	}).Debug("Finished starting disassociation")

	return id, nil
}

func acquireLock(ctx context.Context, tx *sql.Tx, table string, id int) error {
	_, err := tx.ExecContext(ctx, `
SELECT pg_advisory_xact_lock(
                               (SELECT oid
                                FROM pg_class
                                WHERE relname = $1)::int, $2)
`, table, id)
	err = errors.Wrapf(err, "Could not acquire advisory lock on table %s, id %d", table, id)
	return err
}

func (vpcService *vpcService) finishDisassociation(ctx context.Context, slowTx *sql.Tx, session *ec2wrapper.EC2Session, id int) error {
	ctx, span := trace.StartSpan(ctx, "finishDisassociation")
	defer span.End()

	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	if err := lookupFault(ctx, beforeSelectedDisassociationFaultKey).call(ctx); err != nil {
		return err
	}

	err := acquireLock(ctx, slowTx, "branch_eni_attachments", id)
	if err != nil {
		err = errors.Wrap(err, "Unable to acquire lock on branch_eni_attachments table")
		tracehelpers.SetStatus(err, span)
		return err
	}

	row := slowTx.QueryRowContext(ctx, `
SELECT branch_eni_attachments.disassociation_token,
       branch_eni_attachments.association_id,
       branch_eni_attachments.state,
       branch_eni_attachments.error_code,
       branch_eni_attachments.error_message,
       branch_eni_attachments.force,
       branch_eni_attachments.branch_eni,
       branch_eni_attachments.trunk_eni,
       trunk_enis.account_id,
       trunk_enis.region
FROM branch_eni_attachments
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
WHERE branch_eni_attachments.id = $1
`, id)

	logger.G(ctx).Debug("selected from branch_eni_attachments table")
	var errorCode, errorMessage sql.NullString
	var token, associationID, state, accountID, region, branchENI, trunkENI string
	var force sql.NullBool

	err = row.Scan(&token, &associationID, &state, &errorCode, &errorMessage, &force, &branchENI, &trunkENI, &accountID, &region)
	if err == sql.ErrNoRows {
		// The only way that this could have happened is if the work was "successful"
		return nil
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan association action")
		tracehelpers.SetStatus(err, span)
		return err
	}
	span.AddAttributes(
		trace.StringAttribute("branch", branchENI),
		trace.StringAttribute("trunk", trunkENI),
		trace.StringAttribute("associationID", associationID),
	)
	if err := lookupFault(ctx, afterSelectedDisassociationFaultKey).call(ctx, associationID); err != nil {
		return err
	}
	// Dope
	switch state {
	case unattaching:
		// Noop, it's expected to be in this state
	case unattached:
		// Success
		return nil
	default:
		err = fmt.Errorf("branch ENI disassociation in unknown state %q", state)
		tracehelpers.SetStatus(err, span)
		return err
	}

	if (force.Valid && !force.Bool) || !force.Valid {
		var fastTx *sql.Tx
		var err2 error
	restart:
		if fastTx != nil {
			_ = fastTx.Rollback()
		}
		fastTx, err = beginSerializableTx(ctx, vpcService.db)
		if err != nil {
			err = errors.Wrap(err, "Cannot start serializable transaction")
			tracehelpers.SetStatus(err, span)
			return err
		}
		defer func(tx *sql.Tx) {
			_ = tx.Rollback()
		}(fastTx)

		err = hasAssignments(ctx, fastTx, associationID)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Disassociation is not forced, but has assignments")
			_, err2 = slowTx.ExecContext(ctx,
				"UPDATE branch_eni_attachments SET state = 'attached', unattachment_completed_by = $1, unattachment_completed_at = now(), error_code = $2, error_message = $3  WHERE id = $4",
				vpcService.hostname, "hasAssignments", err.Error(), id)
			if isSerializationFailure(err2) {
				goto restart
			}
			if err2 != nil {
				err2 = errors.Wrap(err2, "Unable to update branch_eni_actions_disassociate table to mark action as failed")
				logger.G(ctx).WithError(err2).Error()
				tracehelpers.SetStatus(err2, span)
				return err2
			}

			err2 = fastTx.Commit()
			if isSerializationFailure(err2) {
				goto restart
			}
			if err2 != nil {
				err2 = errors.Wrap(err2, "Unable to commit to branch_eni_actions_disassociate table to mark action as failed")
				logger.G(ctx).WithError(err2).Error()
				tracehelpers.SetStatus(err2, span)
				return err2
			}

			err = newIrrecoverableError(err)
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	if session == nil {
		session, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: region})
		if err != nil {
			err = errors.Wrap(err, "Could not get session")
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	_, err = session.DisassociateTrunkInterface(ctx, ec2.DisassociateTrunkInterfaceInput{
		AssociationId: aws.String(associationID),
		ClientToken:   aws.String(token),
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to disassociate trunk network interface")
		awsErr := ec2wrapper.RetrieveEC2Error(err)
		// This likely means that the disassociation never succeeded.
		// Although, we should check for error codes like
		if awsErr == nil {
			err = errors.Wrap(err, "Unable to disassociate network interface due to non-AWS issues")
			tracehelpers.SetStatus(err, span)
			return err
		}
		if vpcerrors.IsRetryable(err) {
			return ec2wrapper.HandleEC2Error(err, span)
		}

		if awsErr.Code() != "InvalidAssociationID.NotFound" {
			logger.G(ctx).WithError(awsErr).Error("Unable to disassociate trunk network interface due to underlying AWS issue")
			return ec2wrapper.HandleEC2Error(err, span)
		}
		logger.G(ctx).WithError(awsErr).Warning("association ID not found in AWS")
	}

	err = vpcService.finishDisassociationDoUpdate(ctx, id)
	if err != nil {
		err = errors.Wrap(err, "Unable to finish updating disassociation status")
		tracehelpers.SetStatus(err, span)
	}

	return nil
}

func (vpcService *vpcService) finishDisassociationDoUpdate(ctx context.Context, id int) error {
	ctx, span := trace.StartSpan(ctx, "finishDisassociationDoUpdate")
	defer span.End()

	var fastTx *sql.Tx
	var err error

retry_update:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Cannot start serializable transaction to update state to unattached")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	_, err = fastTx.ExecContext(ctx, "UPDATE branch_eni_attachments SET state = 'unattached', unattachment_completed_by = $2, unattachment_completed_at = now() WHERE id = $1", id, vpcService.hostname)
	if isSerializationFailure(err) {
		goto retry_update
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch_eni_actions_disassociate table to mark action as completed")
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err = fastTx.ExecContext(ctx, "SELECT pg_notify('branch_eni_unattachments_finished', $1)", strconv.Itoa(id))
	if isSerializationFailure(err) {
		goto retry_update
	}
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_unattachments_finished")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = fastTx.Commit()
	if isSerializationFailure(err) {
		goto retry_update
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot commit serializable transaction to update state to unattached")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func hasAssignments(ctx context.Context, tx *sql.Tx, associationID string) error {
	rows, err := tx.QueryContext(ctx, "SELECT assignment_id FROM assignments WHERE branch_eni_association = $1", associationID)
	if err != nil {
		err = errors.Wrap(err, "error querying assignments to check if assignments exists")
		return err
	}
	assignments := []string{}
	for rows.Next() {
		var assignmentID string
		err = rows.Scan(&assignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan assignment ID")
			return err
		}
		assignments = append(assignments, assignmentID)
	}
	logger.G(ctx).WithField("assignments", assignments).Debug("Found assignments")
	if l := len(assignments); l > 0 {
		err = fmt.Errorf("%d assignments still assigned to table: %s", l, strings.Join(assignments, ","))
		return err
	}
	return nil
}

// detach a branch ENI from this machine
func (vpcService *vpcService) detachBranchENI(ctx context.Context, tx *sql.Tx, instanceSession *ec2wrapper.EC2Session, trunkENI string) (int, string, string, error) {
	ctx, span := trace.StartSpan(ctx, "detachBranchENI")
	defer span.End()

	row := tx.QueryRowContext(ctx, `
SELECT idx,
       branch_eni,
       association_id
FROM branch_eni_attachments
WHERE trunk_eni = $1
  AND branch_eni_attachments.association_id NOT IN
    (SELECT branch_eni_association
     FROM assignments)
  AND state = 'attached'
ORDER BY COALESCE(
                    (SELECT last_used
                     FROM branch_eni_last_used
                     WHERE branch_eni = branch_eni_attachments.branch_eni), TIMESTAMP 'EPOCH') ASC
LIMIT 1
FOR NO KEY
UPDATE OF branch_eni_attachments SKIP LOCKED
     `, trunkENI)

	var idx int
	var branchENI, associationID string

	err := row.Scan(&idx, &branchENI, &associationID)
	if err == sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(errAllENIsInUse))
		return 0, "", "", errAllENIsInUse
	} else if err != nil {
		err = errors.Wrap(err, "Cannot get unused branch ENI to detach")
		span.SetStatus(traceStatusFromError(err))
		return 0, "", "", err
	}

	err = vpcService.disassociateNetworkInterface(ctx, tx, instanceSession, associationID, false)
	if err != nil {
		err = errors.Wrap(err, "Cannot disassociate network interface")
		tracehelpers.SetStatus(err, span)
		return 0, "", "", err
	}

	return idx, branchENI, associationID, nil
}

func (vpcService *vpcService) associateActionWorker() *actionWorker {
	return &actionWorker{
		db:    vpcService.db,
		dbURL: vpcService.dbURL,
		cb: func(ctx context.Context, tx *sql.Tx, id int) error {
			_, err := vpcService.finishAssociation(ctx, tx, nil, id)
			return err
		},
		creationChannel: "branch_eni_attachments_created",
		finishedChanel:  "branch_eni_attachments_finished",
		name:            "associateWorker2",
		table:           "branch_eni_attachments",
		maxWorkTime:     30 * time.Second,

		pendingState: attaching,

		readyCond: sync.NewCond(&sync.Mutex{}),
	}
}

func (vpcService *vpcService) disassociateActionWorker() *actionWorker {
	return &actionWorker{
		db:    vpcService.db,
		dbURL: vpcService.dbURL,
		cb: func(ctx context.Context, tx *sql.Tx, id int) error {
			return vpcService.finishDisassociation(ctx, tx, nil, id)
		},
		creationChannel: "branch_eni_unattachments_created",
		finishedChanel:  "branch_eni_unattachments_finished",
		name:            "disassociateWorker2",
		table:           "branch_eni_attachments",

		maxWorkTime: 30 * time.Second,

		pendingState: unattaching,

		readyCond: sync.NewCond(&sync.Mutex{}),
	}
}

func (vpcService *vpcService) createBranchENI(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, subnetID string, securityGroups []string) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "createBranchENI")
	defer span.End()

	createNetworkInterfaceInput := ec2.CreateNetworkInterfaceInput{
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         aws.String(subnetID),
		Description:      aws.String(vpcService.branchNetworkInterfaceDescription),
		Groups:           aws.StringSlice(securityGroups),
	}

	output, err := session.CreateNetworkInterface(ctx, createNetworkInterfaceInput)
	logger.G(ctx).WithField("createNetworkInterfaceInput", createNetworkInterfaceInput).Debug("Creating Branch ENI")
	if err != nil {
		err = errors.Wrap(err, "Cannot create branch network interface")
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}
	iface := output.NetworkInterface
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(iface.NetworkInterfaceId)))

	// TODO: verify nothing bad happened and the primary IP of the interface isn't a static addr

	err = insertBranchENIIntoDB(ctx, tx, iface)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert branch ENI into database")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return iface, nil
}

func (vpcService *vpcService) ListBranchToTrunkENIMapping(ctx context.Context, req *titus.GetBranchToTrunkENIMappingRequest) (*titus.GetBranchToTrunkENIMappingResponse, error) {
	ctx, span := trace.StartSpan(ctx, "listBranchToTrunkENIMapping")
	defer span.End()

	mapping := map[string]string{}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly:  true,
		Isolation: sql.LevelRepeatableRead,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, `
	SELECT
	branch_eni,
	trunk_eni
	FROM branch_eni_attachments WHERE state = 'attached'
`)
	if err != nil {
		err = errors.Wrap(err, "Error scanning for all trunk to branch ENI mapping")
		tracehelpers.SetStatus(err, span)
		return &titus.GetBranchToTrunkENIMappingResponse{
			BranchENIMapping: mapping,
		}, err
	}
	defer rows.Close()

	for rows.Next() {
		var branchENIId, trunkENIId string
		err = rows.Scan(&branchENIId, &trunkENIId)
		if err != nil {
			err = errors.Wrap(err, "Error scanning for all trunk to branch ENI mapping")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		logger.G(ctx).WithFields(map[string]interface{}{
			"branchENI": branchENIId,
			"trunkENI":  trunkENIId,
		}).Debug("Returning branch => trunk mapping")
		mapping[branchENIId] = trunkENIId
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Error commiting the sql transaction")
		tracehelpers.SetStatus(err, span)
	}

	return &titus.GetBranchToTrunkENIMappingResponse{
		BranchENIMapping: mapping,
	}, err
}
