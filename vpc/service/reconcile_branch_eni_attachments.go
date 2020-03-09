package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/lib/pq"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

const (
	timeBetweenBranchENIAttachmentReconcilation = time.Minute
)

func (vpcService *vpcService) reconcileBranchENIAttachmentLoop(ctx context.Context, protoItem keyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*regionAccount)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"region":    item.region,
		"accountID": item.accountID,
	})
	for {
		err := vpcService.reconcileBranchAttachmentsENIsForRegionAccount(ctx, item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to reconcile branch ENIs")
		}
		err = waitFor(ctx, timeBetweenBranchENIAttachmentReconcilation)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) reconcileBranchAttachmentsENIsForRegionAccount(ctx context.Context, account *regionAccount) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"accountID": account.accountID,
		"region":    account.region,
	})
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIAttachmentsForRegionAccount")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("region", account.region), trace.StringAttribute("account", account.accountID))

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: account.accountID, Region: account.region})
	if err != nil {
		err = errors.Wrap(err, "Could not get EC2 sesssion")
		tracehelpers.SetStatus(err, span)
		return err
	}

	describeTrunkInterfaceAssociationsInput := ec2.DescribeTrunkInterfaceAssociationsInput{
		MaxResults: aws.Int64(255),
	}

	associations := []*ec2.TrunkInterfaceAssociation{}

	for {
		output, err := session.DescribeTrunkInterfaceAssociations(ctx, describeTrunkInterfaceAssociationsInput)
		if err != nil {
			logger.G(ctx).WithError(err).Error()
			return ec2wrapper.HandleEC2Error(err, span)
		}

		for idx := range output.InterfaceAssociations {
			association := output.InterfaceAssociations[idx]
			associations = append(associations, association)
		}
		if output.NextToken == nil {
			break
		}
		describeTrunkInterfaceAssociationsInput.NextToken = output.NextToken
	}

	associationIDs := sets.NewString()
	// 1. Check that there aren't any stray associations that we do not know about
	for _, assoc := range associations {
		ctx2 := logger.WithField(ctx, "associationID", aws.StringValue(assoc.AssociationId))
		err = vpcService.reconcileBranchENIAttachment(ctx2, session, assoc)
		if err != nil {
			logger.G(ctx2).WithError(err).Error("Could not reconcile association")
		}
		associationIDs.Insert(aws.StringValue(assoc.AssociationId))
	}

	// Now time to do the check the other way -- did we find any associations in the database that didn't return in AWS
	orphanedAssociationIDs, err := vpcService.getDatabaseOrphanedBranchENIAttachments(ctx, account, associationIDs)
	if err != nil {
		err = errors.Wrap(err, "Unable to get orphaned branch ENI attachments")
		tracehelpers.SetStatus(err, span)
		return err
	}

	for _, associationID := range orphanedAssociationIDs.UnsortedList() {
		ctx2 := logger.WithField(ctx, "associationID", associationID)
		err = vpcService.reconcileOrphanedBranchENIAttachment(ctx2, session, associationID)
		if err != nil {
			logger.G(ctx2).WithError(err).Error("Could not reconcile orphaned branch ENI")
		}
	}

	return nil
}

func (vpcService *vpcService) reconcileOrphanedBranchENIAttachment(ctx context.Context, session *ec2wrapper.EC2Session, associationID string) error {
	ctx, span := trace.StartSpan(ctx, "reconcileOrphanedBranchENIAttachment")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	span.AddAttributes(trace.StringAttribute("associationID", associationID))

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "SELECT branch_eni, trunk_eni, idx FROM branch_eni_attachments WHERE association_id = $1 FOR NO KEY UPDATE", associationID)
	var dbBranchENI, dbTrunkENI string
	var idx int
	err = row.Scan(&dbBranchENI, &dbTrunkENI, &idx)
	if err == sql.ErrNoRows {
		logger.G(ctx).Info("Association ID no longer in database, likely race condition")
		return nil
	} else if err != nil {
		err = errors.Wrap(err, "Cannot query database for branch ENI attachment")
		tracehelpers.SetStatus(err, span)
		return err
	}

	// Let's see if there is a pending intent to delete this association. If so, things should be "okay" (soon)
	rows, err := tx.QueryContext(ctx, "SELECT state, id, error_code, error_message FROM branch_eni_actions_disassociate WHERE association_id = $1", associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot query database for branch ENI disassociate actions")
		tracehelpers.SetStatus(err, span)
		return err
	}

	defer func() {
		_ = rows.Close()
	}()

	var result *multierror.Error
	for rows.Next() {
		var state string
		var id int
		var errorCode, errorMessage *sql.NullString
		err = rows.Scan(&state, &id, &errorCode, &errorMessage)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan row from branch_eni_actions_disassociate")
			tracehelpers.SetStatus(err, span)
			return err
		}

		switch state {
		case pendingState:
			logger.G(ctx).Warning("Currently pending action to delete attachment")
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeOK,
				Message: "Currently pending action to delete attachment",
			})
			return nil
		case failedState:
			msg := logger.G(ctx).WithField("id", id)
			if errorCode.Valid {
				msg = msg.WithField("errorCode", errorCode.String)
			}
			if errorMessage.Valid {
				msg = msg.WithField("errorMessage", errorMessage.String)
			}
			msg.Warning("Previous attempts to delete association marked as failed")
			result = multierror.Append(result, fmt.Errorf("Previous attempt to delete association failed (id: %d) with errorCode %q and errorMessage %q", id, errorCode.String, errorMessage.String))
		case completedState:
			result = multierror.Append(result, errors.New("Previous attempt to delete association marked as completed"))
		}
	}

	// So, now we know we have an inconsistency, where an association exists according to the describe call, but does not exist
	// according to our database. It also isn't in the
	_, err = session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice([]string{associationID}),
	})

	if err == nil {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeOK,
			Message: "pointed query returned association",
		})
		logger.G(ctx).Info("pointed query returned association")
		return nil
	}

	awsErr := ec2wrapper.RetrieveEC2Error(err)
	if awsErr == nil {
		err = errors.Wrap(err, "Experienced non-AWS error while trying to query for branch ENI association")
		tracehelpers.SetStatus(err, span)
	}
	if awsErr.Code() != ec2wrapper.InvalidAssociationIDNotFound {
		// "Something else" went wrong"
		logger.G(ctx).WithError(awsErr).Warning("AWS returned error other than association not found")
		return ec2wrapper.HandleEC2Error(err, span)
	}

	// This is bad because there is an association in our database that is not in AWS. We really don't want anyone
	// to assign to it.

	// We can try to do a "safe mode" deletion of it.
	err = vpcService.disassociateNetworkInterface(ctx, tx, session, associationID, false)
	if err != nil {
		err = errors.Wrap(err, "Unable to delete association")
		result = multierror.Append(result, err)
	}

	err = result.ErrorOrNil()
	err = errors.Wrap(err, "Unable to come up with safe reconcilation")
	return err
}

func (vpcService *vpcService) getDatabaseOrphanedBranchENIAttachments(ctx context.Context, account *regionAccount, associationIDs sets.String) (sets.String, error) { //nolint:dupl
	ctx, span := trace.StartSpan(ctx, "getDatabaseOrphanedBranchENIAttachments")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx,
		`
SELECT association_id
FROM branch_eni_attachments
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
JOIN availability_zones on trunk_enis.account_id = availability_zones.account_id AND trunk_enis.az = availability_zones.zone_name
WHERE trunk_enis.account_id = $1
  AND availability_zones.region = $2
  AND association_id != all($3)
`,
		account.region, account.accountID, pq.Array(associationIDs.UnsortedList()))
	if err != nil {
		err = errors.Wrap(err, "Could not query for orphaned branch ENI attachments")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	orphanedENIAttachments := sets.NewString()
	for rows.Next() {
		var associationID string
		err = rows.Scan(&associationID)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan association ID")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		orphanedENIAttachments.Insert(associationID)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return orphanedENIAttachments, nil
}

func (vpcService *vpcService) reconcileBranchENIAttachment(ctx context.Context, session *ec2wrapper.EC2Session, association *ec2.TrunkInterfaceAssociation) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIAttachment")
	defer span.End()

	associationID := aws.StringValue(association.AssociationId)
	span.AddAttributes(trace.StringAttribute("assocationID", associationID))
	// 1. Do we know about this association?
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		// TODO: Consider making this level serializable
	})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "SELECT branch_eni, trunk_eni, idx FROM branch_eni_attachments WHERE association_id = $1", associationID)
	var branchENI, trunkENI string
	var idx int
	err = row.Scan(&branchENI, &trunkENI, &idx)
	if err == sql.ErrNoRows {
		err = reconcileBranchENIAttachmentMissingFromDatabase(ctx, tx, association, session)
		if err != nil {
			// The one case where this could be a real thing is if it was an association when we did the describe
			// but the association has been deleted while the describe loop was running. We don't really account
			// for that.
			err = errors.Wrapf(err, "Could not reconcile eni attachment %q not found in database", associationID)
			tracehelpers.SetStatus(err, span)
			return err
		}

		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction")
			tracehelpers.SetStatus(err, span)
			return err
		}

		return nil
	} else if err != nil {
		err = errors.Wrap(err, "Could not scan branch ENI attachment row")
		tracehelpers.SetStatus(err, span)
		return err
	}

	// TODO: Consider validating the association
	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	return nil
}

func reconcileBranchENIAttachmentMissingFromDatabase(ctx context.Context, tx *sql.Tx, association *ec2.TrunkInterfaceAssociation, session *ec2wrapper.EC2Session) error {
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIAttachmentMissingFromDatabase")
	defer span.End()

	trunkENI := aws.StringValue(association.TrunkInterfaceId)
	branchENI := aws.StringValue(association.BranchInterfaceId)

	// This could very well just be a pending (or completed) reconcilation
	row := tx.QueryRowContext(ctx, "SELECT id FROM branch_eni_actions_associate WHERE branch_eni = $1 AND trunk_eni = $2 AND idx = $3 AND state = 'pending'",
		branchENI, trunkENI, aws.Int64Value(association.VlanId))

	var result *multierror.Error
	var id int
	err := row.Scan(&id)
	if err == sql.ErrNoRows {
		result = multierror.Append(result, errors.New("association not found as pending association in database"))
	} else if err != nil {
		err = errors.Wrap(err, "Could query database for association")
		tracehelpers.SetStatus(err, span)
		return err
	} else {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeOK,
			Message: "Association is in pending state",
		})
		logger.G(ctx).Debug("association is in pending state")
		return nil
	}

	_, err = session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice([]string{aws.StringValue(association.AssociationId)}),
	})
	if err != nil {
		awsErr := ec2wrapper.RetrieveEC2Error(err)
		if awsErr.Code() == "InvalidAssociationID.NotFound" {
			span.SetStatus(trace.Status{
				Code:    trace.StatusCodeOK,
				Message: "Association not found upon requery",
			})
			logger.G(ctx).Debug("Association does not really exist")
			return nil
		}

		err = errors.Wrap(err, "Could not query for association")
		return ec2wrapper.HandleEC2Error(err, span)
	}

	var dbHasTrunkENI bool
	row = tx.QueryRowContext(ctx, "SELECT trunk_eni FROM trunk_enis WHERE trunk_eni = $1 FOR NO KEY UPDATE", trunkENI)
	var dbTrunkENI string
	err = row.Scan(&dbTrunkENI)
	if err == nil {
		dbHasTrunkENI = true
	} else if err != nil && err != sql.ErrNoRows {
		err = errors.Wrapf(err, "Could query trunk_enis for trunk ENI %s", trunkENI)
		tracehelpers.SetStatus(err, span)
		return err
	}

	var dbHasBranchENI bool
	row = tx.QueryRowContext(ctx, "SELECT branch_eni FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", branchENI)
	var dbBranchENI string
	err = row.Scan(&dbBranchENI)
	if err == nil {
		dbHasBranchENI = true
		logger.G(ctx).Debug("Branch ENI not found in database")
	} else if err != nil && err != sql.ErrNoRows {
		err = errors.Wrapf(err, "Could query branch_enis for branch ENI %s", branchENI)
		tracehelpers.SetStatus(err, span)
		return err
	}

	if !dbHasBranchENI && !dbHasTrunkENI {
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeOK,
			Message: "Branch ENI, nor trunk ENI belong to us",
		})
		logger.G(ctx).Debug("Branch ENI, nor trunk ENI belong to us")
		return nil
	}

	var branchENIUnassociated, trunkENIUnassociated bool
	if dbHasBranchENI {
		logger.G(ctx).Warning("branch ENI found in database")
		row = tx.QueryRowContext(ctx, "SELECT trunk_eni, idx, association_id FROM branch_eni_attachments WHERE branch_eni = $1", branchENI)
		var dbTrunkENI, dbAssociationID string
		var idx int
		err = row.Scan(&dbTrunkENI, &idx, &dbAssociationID)
		if err == sql.ErrNoRows {
			result = multierror.Append(result, errors.New("branch ENI found in database, but unassociated"))
			branchENIUnassociated = true
		} else if err != nil {
			err = errors.Wrapf(err, "Could not query branch_eni_attachments for branch ENI %s", branchENI)
			tracehelpers.SetStatus(err, span)
			return err
		} else {
			result = multierror.Append(result, fmt.Errorf("branch ENI found in database, and meant to be associated to trunk ENI %q at idx %d with association ID %q", dbTrunkENI, idx, dbAssociationID))
		}
	}

	if dbHasTrunkENI {
		logger.G(ctx).Warning("trunk ENI found in database")
		row = tx.QueryRowContext(ctx, "SELECT branch_eni, idx, association_id FROM branch_eni_attachments WHERE trunk_eni = $1", trunkENI)
		var dbBranchENI, dbAssociationID string
		var idx int
		err = row.Scan(&dbBranchENI, &idx, &dbAssociationID)
		if err == sql.ErrNoRows {
			result = multierror.Append(result, errors.New("trunk ENI found in database, but unassociated"))
			trunkENIUnassociated = true
		} else if err != nil {
			err = errors.Wrapf(err, "Could not query branch_eni_attachments for trunk ENI %s", trunkENI)
			tracehelpers.SetStatus(err, span)
			return err
		} else {
			result = multierror.Append(result, fmt.Errorf("trunk ENI found in database, and meant to be associated to branch ENI %q at idx %d with association ID %q", dbBranchENI, idx, dbAssociationID))
		}
	}

	if branchENIUnassociated && trunkENIUnassociated {
		logger.G(ctx).Info("Branch ENI, and trunk ENI are both unassociated in database, disassociating in AWS")
		_, err = session.DisassociateTrunkInterface(ctx, ec2.DisassociateTrunkInterfaceInput{
			AssociationId: association.AssociationId,
		})
		awsErr := ec2wrapper.RetrieveEC2Error(err)
		if err == nil {
			return nil
		}
		err = errors.Wrap(err, "Tried to disassociate dangling association")
		if awsErr != nil {
			if awsErr.Code() == ec2wrapper.InvalidAssociationIDNotFound {
				return nil
			}
			return ec2wrapper.HandleEC2Error(err, span)
		}
		result = multierror.Append(result, err)
	}

	return result.ErrorOrNil()
}

func (vpcService *vpcService) getBranchENIRegionAccounts(ctx context.Context) ([]keyedItem, error) {
	ctx, span := trace.StartSpan(ctx, "getBranchENIRegionAccounts")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not start database transaction")
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// TODO: Fix and extract from branch_eni table
	rows, err := tx.QueryContext(ctx, `
SELECT availability_zones.region, branch_enis.account_id FROM branch_enis
JOIN subnets ON branch_enis.subnet_id = subnets.subnet_id
JOIN availability_zones ON subnets.account_id = availability_zones.account_id AND subnets.az = availability_zones.zone_name
GROUP BY availability_zones.region, branch_enis.account_id
`)
	if err != nil {
		return nil, err
	}

	ret := []keyedItem{}
	for rows.Next() {
		var ra regionAccount
		err = rows.Scan(&ra.region, &ra.accountID)
		if err != nil {
			return nil, err
		}
		ret = append(ret, &ra)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return ret, nil
}

func (vpcService *vpcService) reconcileBranchENIAttachmentsLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "reconcile_branch_eni_attachments",
		itemLister: vpcService.getTrunkENIRegionAccounts,
		workFunc:   vpcService.reconcileBranchENIAttachmentLoop,
	}
}
