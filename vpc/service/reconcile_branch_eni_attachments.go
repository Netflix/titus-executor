package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/lib/pq"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
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

	row := tx.QueryRowContext(ctx, "SELECT branch_eni, trunk_eni, idx, state, association_token FROM branch_eni_attachments WHERE association_id = $1 FOR NO KEY UPDATE", associationID)
	var dbBranchENI, dbTrunkENI, dbState string
	var associationToken sql.NullString
	var idx int
	err = row.Scan(&dbBranchENI, &dbTrunkENI, &idx, &dbState, &associationID, &associationToken)
	if err == sql.ErrNoRows {
		logger.G(ctx).Info("Association ID no longer in database, likely race condition")
		return nil
	} else if err != nil {
		err = errors.Wrap(err, "Cannot query database for branch ENI attachment")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if !associationToken.Valid {
		err = errors.New("Association token unset, unable to reconcile")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if dbState == "attaching" || dbState == "attached" {
		logger.G(ctx).WithField("state", dbState).Info("branch ENI is meant to be attached, checking via associate call")
		_, err = session.AssociateTrunkInterface(ctx, ec2.AssociateTrunkInterfaceInput{
			BranchInterfaceId: aws.String(dbBranchENI),
			ClientToken:       aws.String(associationToken.String),
			TrunkInterfaceId:  aws.String(dbTrunkENI),
			VlanId:            aws.Int64(int64(idx)),
		})
		if err == nil {
			return nil
		}
		logger.G(ctx).WithError(err).Warning("Associate call returned error, implying association no longer exists")
	}

	awsErr := ec2wrapper.RetrieveEC2Error(err)
	if awsErr.Code() == "IdempotentParameterMismatch" {
		// Mark the state of the association as not a thing
		_, err = tx.ExecContext(ctx, "UPDATE branch_eni_attachments SET state = 'unattached' WHERE association_id = $1", associationID)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to mark database state as unattached")
			tracehelpers.SetStatus(err, span)
			return err
		}
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction")
			tracehelpers.SetStatus(err, span)
		}
		return nil
	}

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
  AND (state = 'attaching' OR state = 'attached') 
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
		if err != nil {
			// The one case where this could be a real thing is if it was an association when we did the describe
			// but the association has been deleted while the describe loop was running. We don't really account
			// for that.
			err = errors.Wrapf(err, "Could not reconcile eni attachment %q not found in database", associationID)
			logger.G(ctx).WithError(err).Error("Cannot reconcile attachment")
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

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	return nil
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
