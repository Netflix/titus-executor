package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"k8s.io/client-go/util/workqueue"
)

const (
	maxAssociateTime   = 10 * time.Second
	maxDisssociateTime = 10 * time.Second

	// Branch ENI association / disassociation action states
	completedState = "completed"
	failedState    = "failed"
	pendingState   = "pending"
)

func insertBranchENIIntoDB(ctx context.Context, tx *sql.Tx, iface *ec2.NetworkInterface) error {
	securityGroupIds := make([]string, len(iface.Groups))
	for idx := range iface.Groups {
		securityGroupIds[idx] = aws.StringValue(iface.Groups[idx].GroupId)
	}
	sort.Strings(securityGroupIds)

	_, err := tx.ExecContext(ctx, "INSERT INTO branch_enis (branch_eni, subnet_id, account_id, az, vpc_id, security_groups, modified_at) VALUES ($1, $2, $3, $4, $5, $6, transaction_timestamp()) ON CONFLICT (branch_eni) DO NOTHING",
		aws.StringValue(iface.NetworkInterfaceId),
		aws.StringValue(iface.SubnetId),
		aws.StringValue(iface.OwnerId),
		aws.StringValue(iface.AvailabilityZone),
		aws.StringValue(iface.VpcId),
		pq.Array(securityGroupIds),
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
	var err, underlyingErr error
	var pqErr *pq.Error
	var ok bool

startAssociation:
	id, err = vpcService.startAssociation(ctx, tx, branchENI, trunkENI, idx)
	underlyingErr = err
	for underlyingErr != nil {
		pqErr, ok = underlyingErr.(*pq.Error)
		if ok {
			if pqErr.Code.Name() == "serialization_failure" {
				logger.G(ctx).WithError(pqErr).Info("Retrying start associate transaction")
				goto startAssociation
			}
			break
		}
		underlyingErr = errors.Unwrap(underlyingErr)
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

type persistentError struct {
	err error
}

func (p *persistentError) Unwrap() error {
	return p.err
}

func (p *persistentError) Error() string {
	return p.err.Error()
}

func (p *persistentError) Is(target error) bool {
	_, ok := target.(*persistentError)
	return ok
}

type irrecoverableError struct {
	err error
}

func (p *irrecoverableError) Unwrap() error {
	return p.err
}

func (p *irrecoverableError) Error() string {
	return p.err.Error()
}

func (p *irrecoverableError) Is(target error) bool {
	_, ok := target.(*irrecoverableError)
	return ok
}

func (vpcService *vpcService) finishAssociation(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, id int) (*string, error) {
	ctx, span := trace.StartSpan(ctx, "finishAssociation")
	defer span.End()

	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	row := tx.QueryRowContext(ctx, `
SELECT branch_eni_actions_associate.token,
       branch_eni_actions_associate.association_id,
       branch_eni_actions_associate.branch_eni,
       branch_eni_actions_associate.trunk_eni,
       branch_eni_actions_associate.idx,
       branch_eni_actions_associate.error_code,
       branch_eni_actions_associate.error_message,
       trunk_enis.account_id,
       trunk_enis.region,
       branch_eni_actions_associate.state
FROM branch_eni_actions_associate
JOIN trunk_enis ON branch_eni_actions_associate.trunk_eni = trunk_enis.trunk_eni
WHERE branch_eni_actions_associate.id = $1
FOR NO KEY UPDATE OF branch_eni_actions_associate
`, id)

	var associationID, errorCode, errorMessage sql.NullString
	var token, branchENI, trunkENI, accountID, region, state string
	var idx int

	err := row.Scan(&token, &associationID, &branchENI, &trunkENI, &idx, &errorCode, &errorMessage, &accountID, &region, &state)
	if err == sql.ErrNoRows {
		err = &irrecoverableError{err: fmt.Errorf("Work item %d not found", id)}
		tracehelpers.SetStatus(err, span)
		return nil, err
	} else if err != nil {
		err = errors.Wrap(err, "Cannot scan association action")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	span.AddAttributes(trace.StringAttribute("branch", branchENI), trace.StringAttribute("trunk", trunkENI))

	if state == completedState {
		if associationID.Valid {
			return &associationID.String, nil
		}
		err = errors.New("State is completed, but associationID is null")
		tracehelpers.SetStatus(err, span)
		return nil, err
	} else if state == failedState {
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
	}

	// TODO: When this version of the code is fully rolled out, we can remove this line of code, and just insert the whole branch_eni_attachments
	// at once
	row = tx.QueryRowContext(ctx, "INSERT INTO branch_eni_attachments(branch_eni, trunk_eni, idx, attachment_generation) VALUES ($1, $2, $3, 3) RETURNING id",
		branchENI, trunkENI, idx)
	var branchENIAttachmentID int
	err = row.Scan(&branchENIAttachmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot create row in branch ENI attachments")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if session == nil {
		session, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: region})
		if err != nil {
			err = errors.Wrap(err, "Could not get session")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	output, err := session.AssociateTrunkInterface(ctx, ec2.AssociateTrunkInterfaceInput{
		TrunkInterfaceId:  aws.String(trunkENI),
		BranchInterfaceId: aws.String(branchENI),
		ClientToken:       aws.String(token),
		VlanId:            aws.Int64(int64(idx)),
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to associate trunk network interface")
		awsErr := ec2wrapper.RetrieveEC2Error(err)
		// This likely means that the association never succeeded.
		if awsErr == nil {
			tracehelpers.SetStatus(err, span)
			return nil, err
		}

		requestFailure := ec2wrapper.RetrieveRequestFailure(err)
		if requestFailure != nil {
			logger.G(ctx).WithFields(map[string]interface{}{
				"statusCode": requestFailure.StatusCode(),
				"requestID":  requestFailure.RequestID(),
			}).Error("Retrieved request failure error")
			span.AddAttributes(trace.StringAttribute("requestID", requestFailure.RequestID()))
			if requestFailure.StatusCode() >= 500 && requestFailure.StatusCode() < 600 {
				// We should retry this error
				return nil, ec2wrapper.HandleEC2Error(err, span)
			}
		}
		logger.G(ctx).WithError(awsErr).Error("Unable to associate trunk network interface due to underlying AWS issue")
		_, err2 := tx.ExecContext(ctx,
			"UPDATE branch_eni_actions_associate SET state = 'failed', completed_by = $1, completed_at = now(), error_code = $2, error_message = $3  WHERE id = $4",
			vpcService.hostname, awsErr.Code(), awsErr.Message(), id)
		if err2 != nil {
			logger.G(ctx).WithError(err2).Error("Unable to update branch_eni_actions table to mark action as failed")
			tracehelpers.SetStatus(err, span)
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}

		// We need to delete the row from branch_eni_attachments we inserted earlier
		_, err2 = tx.ExecContext(ctx, "DELETE FROM branch_eni_attachments WHERE id = $1", branchENIAttachmentID)
		if err2 != nil {
			logger.G(ctx).WithError(err2).Error("Unable to delete dangling entry in branch eni attachments table")
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}
		return nil, &persistentError{err: ec2wrapper.HandleEC2Error(err, span)}
	}

	_, err = tx.ExecContext(ctx,
		"UPDATE branch_eni_actions_associate SET state = 'completed', completed_by = $1, completed_at = now(), association_id = $2 WHERE id = $3",
		vpcService.hostname, aws.StringValue(output.InterfaceAssociation.AssociationId), id)
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch_eni_actions table to mark action as completed")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_eni_attachments SET association_id = $1 WHERE id = $2",
		aws.StringValue(output.InterfaceAssociation.AssociationId), branchENIAttachmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch_eni_attachments table with populated attachment")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "SELECT pg_notify('branch_eni_actions_associate_finished', $1)", strconv.Itoa(id))
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_actions_associate_finished")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return output.InterfaceAssociation.AssociationId, nil
}

func (vpcService *vpcService) startAssociation(ctx context.Context, slowTx *sql.Tx, branchENI, trunkENI string, idx int) (_ int, retErr error) {
	ctx, span := trace.StartSpan(ctx, "startAssociation")
	defer span.End()

	ctx = logger.WithFields(ctx, map[string]interface{}{
		"branchENI": branchENI,
		"trunkENI":  trunkENI,
	})

	span.AddAttributes(trace.StringAttribute("branch", branchENI), trace.StringAttribute("trunk", trunkENI))

	// Get that predicate locking action.
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	/* See:
	 * https://www.postgresql.org/docs/9.1/transaction-iso.html
	 * A sequential scan will always necessitate a relation-level predicate lock.
	 * This can result in an increased rate of serialization failures.
	 * It may be helpful to encourage the use of index scans by reducing random_page_cost and/or increasing cpu_tuple_cost.
	 * Be sure to weigh any decrease in transaction rollbacks and restarts against any overall change in query execution time.
	 */
	_, err = tx.ExecContext(ctx, "SET enable_seqscan=false")
	if err != nil {
		err = errors.Wrap(err, "Could not set enable_seqscan to false")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	var id int
	row := tx.QueryRowContext(ctx,
		"SELECT id FROM branch_eni_actions_associate WHERE state = 'pending' AND branch_eni = $1 AND trunk_eni = $2 AND idx = $3", branchENI, trunkENI, idx)
	err = row.Scan(&id)
	if err == nil {
		logger.G(ctx).Debug("Association already in progress")
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		return id, nil
	} else if err != sql.ErrNoRows {
		err = errors.Wrap(err, "Could not query branch_eni_actions_associate for existing requests to associate")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	row = tx.QueryRowContext(ctx,
		"SELECT branch_eni, association_id FROM branch_eni_attachments WHERE trunk_eni = $1 AND idx = $2 LIMIT 1",
		trunkENI, idx)
	var existingBranchENI, existingAssociationID string
	err = row.Scan(&existingBranchENI, &existingAssociationID)

	if err != sql.ErrNoRows {
		_ = tx.Rollback()
		if err != nil {
			err = errors.Wrap(err, "error querying branch_eni_attachments to hold predicate lock")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		err = fmt.Errorf("Conflicting association ID %q already from branch ENI %q on trunk ENI %q at index %d", existingAssociationID, existingBranchENI, trunkENI, idx)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	row = tx.QueryRowContext(ctx,
		"SELECT trunk_eni, association_id FROM branch_eni_attachments WHERE branch_eni = $1 LIMIT 1", branchENI)
	var existingTrunkENIID string
	err = row.Scan(&existingTrunkENIID, &existingAssociationID)
	if err != sql.ErrNoRows {
		_ = tx.Rollback()
		if err != nil {
			err = errors.Wrap(err, "error querying branch_eni_attachments to hold predicate lock")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		err = fmt.Errorf("Conflicting association: Branch ENI %q already associated with trunk ENI %q (association: %s)",
			branchENI, existingTrunkENIID, existingAssociationID)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	// TODO: Consider making a foreign key relationship between branch_eni_actions and branch_eni_attachments
	clientToken := uuid.New().String()
	row = tx.QueryRowContext(ctx,
		"INSERT INTO branch_eni_actions_associate(token, branch_eni, trunk_eni, idx, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		clientToken, branchENI, trunkENI, idx, vpcService.hostname,
	)

	err = row.Scan(&id)
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to insert and scan into branch_eni_actions_associate")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	_, err = tx.ExecContext(ctx, "SELECT pg_notify('branch_eni_actions_associate_created', $1)", strconv.Itoa(id))
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_actions_associate_created")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	_, err = slowTx.ExecContext(ctx, `
SELECT pg_advisory_xact_lock(
                               (SELECT oid
                                FROM pg_class
                                WHERE relname = 'branch_eni_actions_associate')::int, $1)
`, id)
	if err != nil {
		err = errors.Wrap(err, "Could not acquire advisory lock")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
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
		span.SetStatus(traceStatusFromError(err))
		return err
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
	var err, underlyingErr error
	var pqErr *pq.Error
	var ok bool

startDissociation:
	id, err = vpcService.startDissociation(ctx, tx, associationID, force)
	underlyingErr = err
	for underlyingErr != nil {
		pqErr, ok = underlyingErr.(*pq.Error)
		if ok {
			if pqErr.Code.Name() == "serialization_failure" {
				logger.G(ctx).WithError(pqErr).Debug("Retrying transaction")
				goto startDissociation
			}
			break
		}
		underlyingErr = errors.Unwrap(underlyingErr)
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to start disassociation")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = lookupFault(ctx, disassociateFaultKey).call(ctx)
	if err != nil {
		return err
	}

	logger.G(ctx).Debug("Finishing disassociation")
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

	// Get that predicate locking action.
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	/* See:
	 * https://www.postgresql.org/docs/9.1/transaction-iso.html
	 * A sequential scan will always necessitate a relation-level predicate lock.
	 * This can result in an increased rate of serialization failures.
	 * It may be helpful to encourage the use of index scans by reducing random_page_cost and/or increasing cpu_tuple_cost.
	 * Be sure to weigh any decrease in transaction rollbacks and restarts against any overall change in query execution time.
	 */
	_, err = tx.ExecContext(ctx, "SET enable_seqscan=false")
	if err != nil {
		err = errors.Wrap(err, "Could not set enable_seqscan to false")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	var id int
	row := tx.QueryRowContext(ctx, "SELECT id FROM branch_eni_actions_disassociate WHERE association_id = $1 AND state = 'pending'", associationID)
	err = row.Scan(&id)
	if err == nil {
		logger.G(ctx).Debug("Disassociation already in progress")
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction")
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
		return id, nil
	} else if err != sql.ErrNoRows {
		err = errors.Wrap(err, "Could not query branch_eni_actions_disassociate for existing requests to disassociate")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	// Technically, none of this is neccessary, because the step to do the INSERT will fail
	// since the failure of the foreign key constraint
	//
	// But this makes nicer error messages
	row = tx.QueryRowContext(ctx, "SELECT branch_eni, trunk_eni FROM branch_eni_attachments WHERE association_id = $1",
		associationID)
	var branchENI, trunkENI string
	err = row.Scan(&branchENI, &trunkENI)

	if err == sql.ErrNoRows {
		_ = tx.Rollback()
		err = fmt.Errorf("Association ID %q not found in branch_eni_attachments", associationID)
		tracehelpers.SetStatus(err, span)
		return 0, err
	} else if err != nil {
		_ = tx.Rollback()
		err = errors.Wrap(err, "error querying branch_eni_attachments to check attachment exists")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	span.AddAttributes(
		trace.StringAttribute("branch", branchENI),
		trace.StringAttribute("trunk", trunkENI),
	)

	if !force {
		err = hasAssignments(ctx, tx, associationID)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return 0, err
		}
	}

	clientToken := uuid.New().String()
	row = tx.QueryRowContext(ctx,
		"INSERT INTO branch_eni_actions_disassociate(token, association_id, created_by, force) VALUES ($1, $2, $3, $4) RETURNING id",
		clientToken, associationID, vpcService.hostname, force)

	err = row.Scan(&id)
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to insert and scan into branch_eni_actions_disassociate")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}
	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	_, err = tx.ExecContext(ctx, "SELECT pg_notify('branch_eni_actions_disassociate_created', $1)", strconv.Itoa(id))
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_actions_disassociate_created")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	_, err = slowTx.ExecContext(ctx, `
SELECT pg_advisory_xact_lock(
                               (SELECT oid
                                FROM pg_class
                                WHERE relname = 'branch_eni_actions_disassociate')::int, $1)
`, id)
	if err != nil {
		err = errors.Wrap(err, "Could not acquire advisory lock")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	logger.G(ctx).WithFields(map[string]interface{}{
		"associationID": associationID,
	}).Debug("Finished starting disassociation")

	return id, nil
}

func (vpcService *vpcService) finishDisassociation(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, id int) error {
	ctx, span := trace.StartSpan(ctx, "finishDisassociation")
	defer span.End()

	span.AddAttributes(trace.Int64Attribute("id", int64(id)))

	logger.G(ctx).Debug("Running before selected disassociation fault key")

	if err := lookupFault(ctx, beforeSelectedDisassociationFaultKey).call(ctx); err != nil {
		return err
	}

	logger.G(ctx).Debug("Running select from branch_eni_actions_disassociate table")

	row := tx.QueryRowContext(ctx, `
SELECT branch_eni_actions_disassociate.token,
       branch_eni_actions_disassociate.association_id,
       branch_eni_actions_disassociate.state,
       branch_eni_actions_disassociate.error_code,
       branch_eni_actions_disassociate.error_message,
       branch_eni_actions_disassociate.force,
       branch_eni_attachments.branch_eni,
       branch_eni_attachments.trunk_eni,
       trunk_enis.account_id,
       trunk_enis.region
FROM branch_eni_actions_disassociate
JOIN branch_eni_attachments ON branch_eni_actions_disassociate.association_id = branch_eni_attachments.association_id
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
WHERE branch_eni_actions_disassociate.id = $1
FOR NO KEY UPDATE OF branch_eni_actions_disassociate
`, id)

	logger.G(ctx).Debug("selected from branch_eni_actions_disassociate table")

	if err := lookupFault(ctx, afterSelectedDisassociationFaultKey).call(ctx); err != nil {
		return err
	}
	var errorCode, errorMessage sql.NullString
	var token, associationID, state, accountID, region, branchENI, trunkENI string
	var force bool

	err := row.Scan(&token, &associationID, &state, &errorCode, &errorMessage, &force, &branchENI, &trunkENI, &accountID, &region)
	if err == sql.ErrNoRows {
		// The only way that this could have happened is if the work was "successful"
		return nil
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan association action")
		tracehelpers.SetStatus(err, span)
		return err
	}
	span.AddAttributes(trace.StringAttribute("branch", branchENI), trace.StringAttribute("trunk", trunkENI))

	// Dope
	switch state {
	case pendingState:
		// Noop, it's expected to be in this state
	case completedState:
		// Success
		return nil
	case failedState:
		if !errorCode.Valid {
			err = errors.New("state of disassociation failed, but errorCode is null")
			tracehelpers.SetStatus(err, span)
			return err
		}
		if !errorMessage.Valid {
			err = errors.New("state of disassociation failed, but errorMessage is null")
			tracehelpers.SetStatus(err, span)
			return err
		}
		err = fmt.Errorf("Request failed with code: %q, message: %q", errorCode.String, errorMessage.String)
		tracehelpers.SetStatus(err, span)
		return err
	default:
		err = fmt.Errorf("branch ENI disassociation in unknown state %q", state)
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err = tx.ExecContext(ctx, "SELECT FROM branch_eni_attachments WHERE association_id = $1 FOR UPDATE OF branch_eni_attachments", associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot select row from branch_eni_attachments to lock")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if !force {
		err = hasAssignments(ctx, tx, associationID)
		if err != nil {
			_, err2 := tx.ExecContext(ctx,
				"UPDATE branch_eni_actions_disassociate SET state = 'failed', completed_by = $1, completed_at = now(), error_code = $2, error_message = $3  WHERE id = $4",
				vpcService.hostname, "hasAssignments", err.Error(), id)
			if err2 != nil {
				logger.G(ctx).WithError(err2).Error("Unable to update branch_eni_actions_disassociate table to mark action as failed")
				tracehelpers.SetStatus(err, span)
				return ec2wrapper.HandleEC2Error(err, span)
			}
			err = &irrecoverableError{err: err}
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
			tracehelpers.SetStatus(err, span)
			return err
		}
		requestFailure := ec2wrapper.RetrieveRequestFailure(err)
		if requestFailure != nil {
			logger.G(ctx).WithFields(map[string]interface{}{
				"statusCode": requestFailure.StatusCode(),
				"requestID":  requestFailure.RequestID(),
			}).Error("Retrieved request failure error")
			span.AddAttributes(trace.StringAttribute("requestID", requestFailure.RequestID()))
			if requestFailure.StatusCode() >= 500 && requestFailure.StatusCode() < 600 {
				// We should retry this error
				return ec2wrapper.HandleEC2Error(err, span)
			}
		}
		if awsErr.Code() != "InvalidAssociationID.NotFound" {
			logger.G(ctx).WithError(awsErr).Error("Unable to disassociate trunk network interface due to underlying AWS issue")
			_, err2 := tx.ExecContext(ctx,
				"UPDATE branch_eni_actions_disassociate SET state = 'failed', completed_by = $1, completed_at = now(), error_code = $2, error_message = $3  WHERE id = $4",
				vpcService.hostname, awsErr.Code(), awsErr.Message(), id)
			if err2 != nil {
				logger.G(ctx).WithError(err2).Error("Unable to update branch_eni_actions_disassociate table to mark action as failed")
				tracehelpers.SetStatus(err, span)
				return ec2wrapper.HandleEC2Error(err, span)
			}
			return &persistentError{err: ec2wrapper.HandleEC2Error(err, span)}
		}
		logger.G(ctx).WithError(awsErr).Warning("association ID not found in AWS, this shouldn't happen (due to the idempotency token)")
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_eni_actions_disassociate SET state = 'completed' WHERE id = $1", id)
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch_eni_actions_disassociate table to mark action as completed")
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).Debug("Successfully finished disassociating ENI")
	// Funnily enough I think this actually deletes the disassociation row
	_, err = tx.ExecContext(ctx, "DELETE FROM branch_eni_attachments WHERE association_id = $1", associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot delete from branch_eni_attachments table")
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err = tx.ExecContext(ctx, "SELECT pg_notify('branch_eni_actions_disassociate_finished', $1)", strconv.Itoa(id))
	if err != nil {
		// These errors might largely be recoverable, so you know, deal with that
		err = errors.Wrap(err, "Unable to notify of branch_eni_actions_disassociate_finished")
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

type listenerEvent struct {
	listenerEvent pq.ListenerEventType
	err           error
}

type actionWorker struct {
	db    *sql.DB
	dbURL string

	// The sql.tx part is useful for both use cases right now, but it might make sense to remove it in the future
	cb func(context.Context, *sql.Tx, int) error

	creationChannel string
	finishedChanel  string
	name            string
	table           string

	maxWorkTime time.Duration
}

func (actionWorker *actionWorker) loop(ctx context.Context, item keyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx = logger.WithField(ctx, "actionWorker", actionWorker.name)

	listenerEventCh := make(chan listenerEvent, 10)
	eventCallback := func(event pq.ListenerEventType, err error) {
		listenerEventCh <- listenerEvent{listenerEvent: event, err: err}
	}
	pqListener := pq.NewListener(actionWorker.dbURL, 10*time.Second, 2*time.Minute, eventCallback)
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

	wq := workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), actionWorker.name)
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
			logger.G(ctx).WithError(err).Error("Worker exiting")
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
			case pq.ListenerEventDisconnected:
				wq.ShutDown()
				logger.G(ctx).WithError(ev.err).Error("Disconnected from postgres, stopping work")
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
			return nil
		}

		// Try to lock it for one second. It'll error out otherwise
		_, err = tx.ExecContext(ctx, `
SELECT pg_advisory_xact_lock(
                               (SELECT oid
                                FROM pg_class
                                WHERE relname = $1)::int, $2)
`, actionWorker.table, id)
		if err != nil {
			err = errors.Wrap(err, "Could not acquire lock on object")
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error()
			return nil
		}

		logger.G(ctx).Debug("Got lock?")

		_, err = tx.ExecContext(ctx, "set lock_timeout = 0")
		if err != nil {
			err = errors.Wrap(err, "Cannot reset lock timeout to 0 (infinity)")
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error()
			return nil
		}

		err = actionWorker.cb(ctx, tx, id)
		// TODO: Consider updating the table state here
		if errors.Is(err, &persistentError{}) {
			logger.G(ctx).WithError(err).Error("Experienced persistent error, still committing database state (assuming function updated state to failed)")
		} else if errors.Is(err, &irrecoverableError{}) {
			logger.G(ctx).WithError(err).Errorf("Experienced irrecoverable error, still committing database state (assuming function updated state to failed)")
		} else if err != nil {
			tracehelpers.SetStatus(err, span)
			logger.G(ctx).WithError(err).Error("Failed to process item")
			wq.AddRateLimited(item)
			return nil
		}
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

	rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT id FROM %s WHERE state = 'pending'", actionWorker.table)) //nolint:gosec
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

func (actionWorker *actionWorker) longLivedTask() longLivedTask {
	return longLivedTask{
		workFunc:   actionWorker.loop,
		itemLister: nilItemEnumerator,
		taskName:   actionWorker.name,
	}
}

func (vpcService *vpcService) associateActionWorker() *actionWorker {
	return &actionWorker{
		db:    vpcService.db,
		dbURL: vpcService.dbURL,
		cb: func(ctx context.Context, tx *sql.Tx, id int) error {
			_, err := vpcService.finishAssociation(ctx, tx, nil, id)
			return err
		},
		creationChannel: "branch_eni_actions_associate_created",
		finishedChanel:  "branch_eni_actions_associate_finished",
		name:            "associateWorker",
		table:           "branch_eni_actions_associate",
		maxWorkTime:     30 * time.Second,
	}
}

func (vpcService *vpcService) disassociateActionWorker() *actionWorker {
	return &actionWorker{
		db:    vpcService.db,
		dbURL: vpcService.dbURL,
		cb: func(ctx context.Context, tx *sql.Tx, id int) error {
			return vpcService.finishDisassociation(ctx, tx, nil, id)
		},
		creationChannel: "branch_eni_actions_disassociate_created",
		finishedChanel:  "branch_eni_actions_disassociate_finished",
		name:            "disassociateWorker",
		table:           "branch_eni_actions_disassociate",

		maxWorkTime: 30 * time.Second,
	}
}

func (vpcService *vpcService) createBranchENI(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, subnetID string, securityGroups []string) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "createBranchENI")
	defer span.End()

	createNetworkInterfaceInput := ec2.CreateNetworkInterfaceInput{
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         aws.String(subnetID),
		Description:      aws.String(vpc.BranchNetworkInterfaceDescription),
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
