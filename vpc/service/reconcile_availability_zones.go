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

func (vpcService *vpcService) reconcileAvailabilityZonesRegionAccount(ctx context.Context, account regionAccount, tx *sql.Tx) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileAvailabilityZonesRegionAccount")
	defer span.End()
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
	}).Info("Beginning reconcilation of availability zones")

	ec2client := ec2.New(session.Session)
	describeAvailabilityZonesOutput, err := ec2client.DescribeAvailabilityZonesWithContext(ctx, &ec2.DescribeAvailabilityZonesInput{})
	if err != nil {
		err = errors.Wrap(err, "Could not describe availability zones")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	for _, az := range describeAvailabilityZonesOutput.AvailabilityZones {
		_, err = tx.ExecContext(ctx, `
INSERT INTO availability_zones(account_id, group_name, network_border_group, region, zone_id, zone_name)
VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING
    `,
			account.accountID,
			aws.StringValue(az.GroupName),
			aws.StringValue(az.NetworkBorderGroup),
			aws.StringValue(az.RegionName),
			aws.StringValue(az.ZoneId),
			aws.StringValue(az.ZoneName))
		if err != nil {
			err = errors.Wrap(err, "Could insert AZ")
			span.SetStatus(traceStatusFromError(err))
			return err
		}
	}

	return nil
}
