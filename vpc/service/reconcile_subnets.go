package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/metrics"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/go-multierror"
	"github.com/lib/pq"
	"github.com/m7shapan/cidr"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	timeBetweenSubnetReconcilation = 2 * time.Minute
)

func (vpcService *vpcService) getRegionAccounts(ctx context.Context) ([]data.KeyedItem, error) {
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

	ret := []data.KeyedItem{}
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

func (vpcService *vpcService) doReconcileSubnetsForRegionAccountLoop(ctx context.Context, protoItem data.KeyedItem) error {
	item := protoItem.(*regionAccount)
	for {
		ctx = logger.WithFields(ctx, map[string]interface{}{
			"region":    item.region,
			"accountID": item.accountID,
		})
		start := time.Now()
		err := vpcService.doReconcileSubnetsForRegionAccount(ctx, item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to reconcile subnets")
			stats.Record(ctx, metrics.ErrorReconcileSubnetsCount.M(1))
		} else {
			stats.Record(ctx, metrics.ReconcileSubnetsLatency.M(time.Since(start).Milliseconds()))
		}
		err = waitFor(ctx, timeBetweenSubnetReconcilation)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doReconcileSubnetsForRegionAccount(ctx context.Context, account *regionAccount) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileSubnetsForRegionAccount")
	defer span.End()

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

	logger.G(ctx).Info("Beginning reconcilation of subnets")

	ec2client := vpcService.ec2.NewEC2(session.Session)

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

	var result *multierror.Error
	for _, subnet := range subnets {
		err = vpcService.insertSubnet(ctx, subnet)
		if err != nil {
			logger.G(ctx).WithField("subnet", aws.StringValue(subnet.SubnetId)).WithError(err).Error("Could not insert subnet")
			result = multierror.Append(result, err)
		}
	}

	err = result.ErrorOrNil()
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) insertSubnet(ctx context.Context, subnet *ec2.Subnet) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "insertSubnet")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("subnet", aws.StringValue(subnet.SubnetId)),
	)

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = fmt.Errorf("Could not begin tx: %w", err)
		tracehelpers.SetStatus(err, span)
	}

	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "SELECT id, cidr6 FROM subnets WHERE subnet_id = $1", aws.StringValue(subnet.SubnetId))
	var id int
	var cidr6 sql.NullString
	err = row.Scan(&id, &cidr6)
	if err == sql.ErrNoRows {
		row = tx.QueryRowContext(ctx, "INSERT INTO subnets(az, az_id, vpc_id, account_id, subnet_id, cidr) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
			aws.StringValue(subnet.AvailabilityZone),
			aws.StringValue(subnet.AvailabilityZoneId),
			aws.StringValue(subnet.VpcId),
			aws.StringValue(subnet.OwnerId),
			aws.StringValue(subnet.SubnetId),
			aws.StringValue(subnet.CidrBlock))
		err = row.Scan(&id)
		if err != nil {
			err = fmt.Errorf("Cannot insert subnet: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
	} else if err != nil {
		err = fmt.Errorf("Cannot select subnet %s from db: %w", aws.StringValue(subnet.SubnetId), err)
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

		if !cidr6.Valid {
			_, err = tx.ExecContext(ctx, "UPDATE subnets SET cidr6 = $1 WHERE id = $2",
				ipnet.String(),
				id,
			)
			if err != nil {
				err = fmt.Errorf("Cannot update / set cidr6: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
		knownPrefixes := sets.NewString()
		rows, err := tx.QueryContext(ctx, "SELECT prefix FROM subnet_usable_prefix WHERE subnet_id = $1", id)
		if err != nil {
			err = fmt.Errorf("Could not query subnet_usable_prefix: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
		for rows.Next() {
			var prefix string
			err = rows.Scan(&prefix)
			if err != nil {
				err = fmt.Errorf("Could not scan prefix: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}

			knownPrefixes.Insert(prefix)
		}

		allPrefixes := sets.NewString()
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
			allPrefixes.Insert(cidr.String())
		}

		newPrefixes := allPrefixes.Difference(knownPrefixes)

		if newPrefixes.Len() > 0 {
			_, err = tx.ExecContext(ctx, `
INSERT INTO subnet_usable_prefix (subnet_id, prefix)
SELECT $1, unnest($2::cidr[])
`,
				id, pq.Array(newPrefixes.UnsortedList()))
			if err != nil {
				err = fmt.Errorf("Cannot update / set cidr6: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		err = fmt.Errorf("Cannot commit transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}
