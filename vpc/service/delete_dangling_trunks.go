package service

import (
	"context"
	"database/sql"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

func (vpcService *vpcService) deleteDanglingTrunksForRegionAccount(ctx context.Context, account regionAccount, tx *sql.Tx) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIsForRegionAccount")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("region", account.region), trace.StringAttribute("account", account.accountID))
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: account.accountID,
		Region:    account.region,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get session")
		return err
	}

	ec2client := ec2.New(session.Session)
	// Find unattached ENIs with the titus-managed-trunk and (try) blowing them away
	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpc.TrunkNetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("status"),
				Values: aws.StringSlice([]string{"available"}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{account.accountID}),
			},
		},
		MaxResults: aws.Int64(1000),
	}
	badENIs := []*ec2.NetworkInterface{}
	for {
		output, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
		if err != nil {
			err = ec2wrapper.HandleEC2Error(err, span)
			err = errors.Wrap(err, "Cannot describe trunk network interfaces")
			return err
		}
		badENIs = append(badENIs, output.NetworkInterfaces...)
		if output.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = output.NextToken
	}

	for _, eni := range badENIs {
		_, err = ec2client.DeleteNetworkInterfaceWithContext(ctx, &ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: eni.NetworkInterfaceId,
		})
		if err != nil {
			logger.G(ctx).WithError(err).Error("Cannot delete dangling trunk ENI")
		}
	}
	return nil
}

func (vpcService *vpcService) getTrunkENIRegionAccounts(ctx context.Context) ([]regionAccount, error) {
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
	rows, err := tx.QueryContext(ctx, "SELECT region, account_id FROM trunk_enis GROUP BY region, account_id")
	if err != nil {
		return nil, err
	}

	ret := []regionAccount{}
	for rows.Next() {
		var ra regionAccount
		err = rows.Scan(&ra.region, &ra.accountID)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ra)
	}

	_ = tx.Commit()
	return ret, nil
}
