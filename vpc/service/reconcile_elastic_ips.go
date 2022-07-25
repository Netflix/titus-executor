package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

type Tags map[string]string

func (t Tags) Value() (driver.Value, error) {
	j, err := json.Marshal(t)
	return j, err
}

func (vpcService *vpcService) reconcileEIPsForRegionAccount(ctx context.Context, protoAccount data.KeyedItem, tx *sql.Tx) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileEIPsForRegionAccount")
	defer span.End()

	account := protoAccount.(*regionAccount)
	span.AddAttributes(trace.StringAttribute("region", account.region), trace.StringAttribute("account", account.accountID))
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: account.accountID,
		Region:    account.region,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get session")
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).WithFields(map[string]interface{}{
		"region":    account.region,
		"accountID": account.accountID,
	}).Info("Beginning reconcilation of EIPs")

	_, err = tx.ExecContext(ctx, "CREATE TEMPORARY TABLE IF NOT EXISTS known_elastic_ips (allocation_id TEXT PRIMARY KEY, account_id text, public_ip inet, tags jsonb, network_border_group text) ON COMMIT DROP")
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return errors.Wrap(err, "Could not create temporary table for known eips")
	}

	ec2client := vpcService.ec2.NewEC2(session.Session)
	describeAddressesInput := ec2.DescribeAddressesInput{}
	describeAddressesOutput, err := ec2client.DescribeAddressesWithContext(ctx, &describeAddressesInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not elastic IPs")
		return ec2wrapper.HandleEC2Error(err, span)
	}
	for _, eip := range describeAddressesOutput.Addresses {

		tags := Tags{}
		for _, tag := range eip.Tags {
			tags[aws.StringValue(tag.Key)] = aws.StringValue(tag.Value)
		}

		_, err = tx.ExecContext(ctx, "INSERT INTO known_elastic_ips(allocation_id, account_id, public_ip, tags, network_border_group) VALUES ($1, $2, $3, $4, $5)",
			aws.StringValue(eip.AllocationId),
			account.accountID,
			aws.StringValue(eip.PublicIp),
			tags,
			aws.StringValue(eip.NetworkBorderGroup),
		)
		if err != nil {
			err = errors.Wrap(err, "Could not update known_elastic_ips")
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	_, err = tx.ExecContext(ctx, `
	INSERT INTO elastic_ips(allocation_id, account_id, public_ip, tags, network_border_group, region)
	SELECT allocation_id,
		   account_id,
		   public_ip,
		   tags,
	       network_border_group,
	       $1
	FROM known_elastic_ips ON CONFLICT (allocation_id) DO
	UPDATE
	SET tags = excluded.tags
	WHERE elastic_ips.tags != excluded.tags
	  `, account.region)

	if err != nil {
		err = errors.Wrap(err, "Could not insert new elastic IPs")
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err = tx.ExecContext(ctx, `
	DELETE
	FROM elastic_ips
	WHERE account_id = $1
	  AND region = $2
	  AND allocation_id NOT IN
		(SELECT allocation_id
		 FROM known_elastic_ips)
	`, account.accountID, account.region)

	if err != nil {
		err = errors.Wrap(err, "Could not delete elastic IPs")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}
