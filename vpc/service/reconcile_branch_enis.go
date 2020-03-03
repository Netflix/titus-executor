package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"

	"github.com/lib/pq"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

func (vpcService *vpcService) reconcileBranchENIsForRegionAccount(ctx context.Context, protoItem keyedItem, tx *sql.Tx) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIsForRegionAccount")
	defer span.End()
	account := protoItem.(*regionAccount)
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
	}).Info("Beginning reconcilation of branch ENIs")

	_, err = tx.ExecContext(ctx, "CREATE TEMPORARY TABLE IF NOT EXISTS known_branch_enis (branch_eni TEXT PRIMARY KEY, account_id text, subnet_id text, az text, vpc_id text, state text, security_groups text array) ON COMMIT DROP ")
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return errors.Wrap(err, "Could not create temporary table for known branch enis")
	}

	ec2client := ec2.New(session.Session)
	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpc.BranchNetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{account.accountID}),
			},
		},
		MaxResults: aws.Int64(1000),
	}

	for {
		output, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &describeNetworkInterfacesInput)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Could not describe network interfaces")
			return ec2wrapper.HandleEC2Error(err, span)
		}
		for _, branchENI := range output.NetworkInterfaces {
			securityGroups := make([]string, len(branchENI.Groups))
			for idx := range branchENI.Groups {
				group := branchENI.Groups[idx]
				securityGroups[idx] = aws.StringValue(group.GroupId)
			}
			sort.Strings(securityGroups)
			_, err = tx.ExecContext(ctx, "INSERT INTO known_branch_enis(branch_eni, account_id, subnet_id, az, vpc_id, state, security_groups) VALUES ($1, $2, $3, $4, $5, $6, $7)",
				aws.StringValue(branchENI.NetworkInterfaceId),
				aws.StringValue(branchENI.OwnerId),
				aws.StringValue(branchENI.SubnetId),
				aws.StringValue(branchENI.AvailabilityZone),
				aws.StringValue(branchENI.VpcId),
				aws.StringValue(branchENI.Status),
				pq.Array(securityGroups),
			)
			if err != nil {
				err = errors.Wrap(err, "Could not update known_branch_enis")
				span.SetStatus(traceStatusFromError(err))
				return err
			}
		}
		if output.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = output.NextToken
	}
	_, err = tx.ExecContext(ctx, `
	INSERT INTO branch_enis(branch_eni, account_id, subnet_id, az, vpc_id, security_groups, modified_at)
	SELECT branch_eni,
		   account_id,
		   subnet_id,
		   az,
		   vpc_id,
		   security_groups,
	       transaction_timestamp()
	FROM known_branch_enis ON CONFLICT (branch_eni) DO
	UPDATE
	SET security_groups = excluded.security_groups,
		modified_at = transaction_timestamp()
	WHERE branch_enis.modified_at < transaction_timestamp()
	  AND (branch_enis.security_groups IS NULL)
	  `)
	if err != nil {
		err = errors.Wrap(err, "Could not insert new branch ENIs")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	// there are two race conditions here. Listing all the ENIs in the account takes ~5 minutes. If the branch ENI was not associated / existed
	// at the beginning of the reconciliation, then we can act upon stale data.

	// Populate branch eni attachments with ENIs that are not in use
	_, err = tx.ExecContext(ctx, "DELETE FROM branch_eni_attachments WHERE branch_eni IN (SELECT branch_eni FROM known_branch_enis WHERE state = 'available') AND created_at < transaction_timestamp()")
	if err != nil {
		err = errors.Wrap(err, "Could not delete unattached branch eni attachments")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	_, err = tx.ExecContext(ctx, `
	DELETE
	FROM branch_enis
	WHERE account_id = $1
	  AND (regexp_match(az, '[a-z]+-[a-z]+-[0-9]+'))[1] = $2
	  AND branch_eni NOT IN
		(SELECT branch_eni
		 FROM known_branch_enis)
	  AND created_at < transaction_timestamp()
	`, account.accountID, account.region)
	if err != nil {
		err = errors.Wrap(err, "Cannot delete removed branch ENIs")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}

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

type regionAccount struct {
	accountID string
	region    string
}

func (ra *regionAccount) key() string {
	return fmt.Sprintf("%s_%s", ra.region, ra.accountID)
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
