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

func (vpcService *vpcService) reconcileTrunkENIsForRegionAccount(ctx context.Context, protoAccount keyedItem, tx *sql.Tx) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileTrunkENIsForRegionAccount")
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
	}).Info("Beginning reconcilation of trunk ENIs")

	_, err = tx.ExecContext(ctx, `create temporary table known_trunk_enis
(
	trunk_eni text,
	account_id text,
	az text,
	subnet_id text,
	vpc_id text
) on commit drop
`)
	if err != nil {
		err = errors.Wrap(err, "Unable to create temporary table known_trunk_enis")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	ec2client := ec2.New(session.Session)
	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpc.TrunkNetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{account.accountID}),
			},
		},
		MaxResults: aws.Int64(1000),
	}
	for {
		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &describeNetworkInterfacesInput)
		if err != nil {
			err = errors.Wrap(err, "Cannot describe network interfaces")
			span.SetStatus(traceStatusFromError(err))
			return err
		}

		for _, iface := range describeNetworkInterfacesOutput.NetworkInterfaces {
			_, err = tx.ExecContext(ctx, "INSERT INTO known_trunk_enis(trunk_eni, account_id, az, subnet_id, vpc_id) VALUES ($1, $2, $3, $4, $5)",
				aws.StringValue(iface.NetworkInterfaceId),
				aws.StringValue(iface.OwnerId),
				aws.StringValue(iface.AvailabilityZone),
				aws.StringValue(iface.SubnetId),
				aws.StringValue(iface.VpcId),
			)
			if err != nil {
				err = errors.Wrap(err, "Could not update known_trunk_enis")
				span.SetStatus(traceStatusFromError(err))
				return err
			}
		}

		if describeNetworkInterfacesOutput.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO trunk_enis(trunk_eni, account_id, created_at, az, subnet_id, vpc_id, region)
SELECT trunk_eni,
       account_id,
       transaction_timestamp(),
       az,
       subnet_id,
       vpc_id,
       $1
FROM known_trunk_enis ON CONFLICT (trunk_eni) DO NOTHING
`, account.region)
	if err != nil {
		err = errors.Wrap(err, "Could not insert new trunk ENIs")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	_, err = tx.ExecContext(ctx, `
DELETE 
FROM trunk_enis
WHERE trunk_eni NOT IN (SELECT trunk_eni FROM known_trunk_enis)
  AND account_id = $1
  AND region = $2
  AND created_at < transaction_timestamp()
`, account.accountID, account.region)
	if err != nil {
		err = errors.Wrap(err, "Could delete existing trunk ENIs")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}
