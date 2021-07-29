package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"net"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/lib/pq"
	"github.com/m7shapan/cidr"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

func (vpcService *vpcService) getRegionAccounts(ctx context.Context) ([]keyedItem, error) {
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
	rows, err := tx.QueryContext(ctx, "SELECT region, account_id FROM accounts")
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

	_ = tx.Commit()
	return ret, nil
}

func (vpcService *vpcService) reconcileSubnetsForRegionAccount(ctx context.Context, protoAccount keyedItem, tx *sql.Tx) (retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileSubnetsForRegionAccount")
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
	}).Info("Beginning reconcilation of subnets")

	ec2client := ec2.New(session.Session)

	describeSubnetsInput := ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{account.accountID}),
			},
		},
	}

	subnets := []*ec2.Subnet{}

	for {
		output, err := ec2client.DescribeSubnetsWithContext(ctx, &describeSubnetsInput)
		if err != nil {
			logger.G(ctx).WithError(err).Error()
			return ec2wrapper.HandleEC2Error(err, span)
		}
		subnets = append(subnets, output.Subnets...)

		if output.NextToken == nil {
			break
		}
		describeSubnetsInput.NextToken = output.NextToken
	}

	for _, subnet := range subnets {
		_, err = tx.ExecContext(ctx, "INSERT INTO subnets(az, az_id, vpc_id, account_id, subnet_id, cidr) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (subnet_id) DO NOTHING",
			aws.StringValue(subnet.AvailabilityZone),
			aws.StringValue(subnet.AvailabilityZoneId),
			aws.StringValue(subnet.VpcId),
			aws.StringValue(subnet.OwnerId),
			aws.StringValue(subnet.SubnetId),
			aws.StringValue(subnet.CidrBlock))
		if err != nil {
			err = errors.Wrap(err, "Cannot insert subnets")
			tracehelpers.SetStatus(err, span)
			return err
		}

		row := tx.QueryRowContext(ctx, "SELECT id FROM subnets WHERE subnet_id = $1", aws.StringValue(subnet.SubnetId))
		var id int
		err = row.Scan(&id)
		if err != nil {
			err = errors.Wrap(err, "Cannot read subnet ID")
			tracehelpers.SetStatus(err, span)
			return err
		}

		if len(subnet.Ipv6CidrBlockAssociationSet) == 1 && aws.StringValue(subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlockState.State) == "associated" {
			_, ipnet, err := net.ParseCIDR(aws.StringValue(subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock))
			if err != nil {
				err = fmt.Errorf("Cannot parse cidr %q: %w", aws.StringValue(subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock), err)
				tracehelpers.SetStatus(err, span)
				return err
			}
			_, err = tx.ExecContext(ctx, "UPDATE subnets SET cidr6 = $1 WHERE id = $2 AND cidr6 IS NULL",
				ipnet.String(),
				id,
			)
			if err != nil {
				err = fmt.Errorf("Cannot update / set cidr6: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}

			cidrs := []string{}
			first := cidr.IPv6tod(ipnet.IP)
			// 48 comes from 128 - 80
			offset := big.NewInt(1 << 48)
			var i int64
			// TODO: Consider not hardcoding this.
			for i = 1; i <= 65535; i++ {
				ip := big.NewInt(0)
				ip = ip.Mul(big.NewInt(i), offset)
				ip = ip.Add(ip, first)
				addr := cidr.DtoIPv6(ip)
				cidr := net.IPNet{
					IP:   addr,
					Mask: net.CIDRMask(80, 128),
				}
				cidrs = append(cidrs, cidr.String())
			}

			_, err = tx.ExecContext(ctx, `
INSERT INTO subnet_usable_prefix (subnet_id, prefix)
SELECT $1, unnest($2::cidr[])
ON CONFLICT (subnet_id, prefix) DO NOTHING 
`,
				id, pq.Array(cidrs))
			if err != nil {
				err = fmt.Errorf("Cannot update / set cidr6: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	return nil
}
