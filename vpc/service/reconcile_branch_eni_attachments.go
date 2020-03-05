package service

import (
	"context"
	"database/sql"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

func (vpcService *vpcService) reconcileBranchENIAttachmentsForRegionAccount(ctx context.Context, protoAccount keyedItem, tx *sql.Tx) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIAttachmentsForRegionAccount")
	defer span.End()
	account := protoAccount.(*regionAccount)
	span.AddAttributes(trace.StringAttribute("region", account.region), trace.StringAttribute("account", account.accountID))
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: account.accountID,
		Region:    account.region,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	logger.G(ctx).WithFields(map[string]interface{}{
		"region":    account.region,
		"accountID": account.accountID,
	}).Info("Beginning reconcilation of branch ENI attachments")

	ec2client := ec2.New(session.Session)

	_, err = tx.ExecContext(ctx, "CREATE TEMPORARY TABLE IF NOT EXISTS known_branch_eni_attachments (branch_eni TEXT PRIMARY KEY, trunk_eni text, idx int, association_id text) ON COMMIT DROP")
	if err != nil {
		return errors.Wrap(err, "Could not create temporary table for known branch enis")
	}

	describeTrunkInterfaceAssociationsInput := ec2.DescribeTrunkInterfaceAssociationsInput{
		MaxResults: aws.Int64(255),
	}

	for {
		output, err := ec2client.DescribeTrunkInterfaceAssociationsWithContext(ctx, &describeTrunkInterfaceAssociationsInput)
		if err != nil {
			logger.G(ctx).WithError(err).Error()
			return ec2wrapper.HandleEC2Error(err, span)
		}
		for _, assoc := range output.InterfaceAssociations {
			_, err = tx.ExecContext(ctx, "INSERT INTO known_branch_eni_attachments(branch_eni, trunk_eni, idx, association_id) VALUES ($1, $2, $3, $4)",
				aws.StringValue(assoc.BranchInterfaceId),
				aws.StringValue(assoc.TrunkInterfaceId),
				aws.Int64Value(assoc.VlanId),
				aws.StringValue(assoc.AssociationId),
			)
			if err != nil {
				return errors.Wrap(err, "Could not update known_branch_enis")
			}
		}
		if output.NextToken == nil {
			break
		}
		describeTrunkInterfaceAssociationsInput.NextToken = output.NextToken
	}

	_, err = tx.ExecContext(ctx, `
	DELETE
	FROM branch_eni_attachments
	WHERE branch_eni IN
		(SELECT branch_eni_attachments.branch_eni
		 FROM branch_eni_attachments
		 JOIN known_branch_eni_attachments ON branch_eni_attachments.branch_eni = known_branch_eni_attachments.branch_eni
		 WHERE branch_eni_attachments.association_id != known_branch_eni_attachments.association_id
		   AND created_at < transaction_timestamp())
	`)
	if err != nil {
		return errors.Wrap(err, "Cannot delete old (bad) branch ENI attachments")
	}
	_, err = tx.ExecContext(ctx, `
	INSERT INTO branch_eni_attachments(branch_eni, trunk_eni, idx, association_id, created_at)
	SELECT branch_eni,
		   trunk_eni,
		   idx,
		   association_id,
		   transaction_timestamp()
	FROM known_branch_eni_attachments WHERE branch_eni NOT IN (SELECT branch_eni FROM branch_eni_attachments)
`)
	if err != nil {
		return errors.Wrap(err, "Could not insert new branch eni attachments")
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
