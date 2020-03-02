package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	warmPoolPerSubnet      = 50
	timeBetweenErrors      = 10 * time.Second
	timeBetweenNoDeletions = 2 * time.Minute
	timeBetweenDeletions   = 5 * time.Second
)

func (vpcService *vpcService) getSubnets(ctx context.Context) ([]keyedItem, error) {
	ctx, span := trace.StartSpan(ctx, "getSubnets")
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
SELECT subnets.az,
       subnets.vpc_id,
       subnets.account_id,
       subnets.subnet_id,
       subnets.cidr,
       availability_zones.region
FROM subnets
JOIN availability_zones ON subnets.az = availability_zones.zone_name AND subnets.account_id = availability_zones.account_id
`)
	if err != nil {
		return nil, err
	}

	ret := []keyedItem{}
	for rows.Next() {
		var s subnet
		err = rows.Scan(&s.az, &s.vpcID, &s.accountID, &s.subnetID, &s.cidr, &s.region)
		if err != nil {
			return nil, err
		}
		ret = append(ret, &s)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return ret, nil
}

func (vpcService *vpcService) deleteExccessBranchesLoop(ctx context.Context, protoItem keyedItem) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*subnet)
	for {
		var resetTime time.Duration
		branchesDeleted, err := vpcService.doDeleteExcessBranches(ctx, item)
		if err != nil {
			logger.G(ctx).WithField("region", item.region).WithField("accountID", item.accountID).WithError(err).Error("Failed to delete excess branches")
			resetTime = timeBetweenErrors
		} else if branchesDeleted {
			resetTime = timeBetweenDeletions
		} else {
			resetTime = timeBetweenNoDeletions
		}
		err = waitFor(ctx, resetTime)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Terminating loop")
			return
		}
	}
}

func (vpcService *vpcService) doDeleteExcessBranches(ctx context.Context, subnet *subnet) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doDeleteExcessBranches")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("subnet", subnet.subnetID),
		trace.StringAttribute("accountID", subnet.accountID),
		trace.StringAttribute("az", subnet.az),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"subnet":    subnet.subnetID,
		"accountID": subnet.accountID,
		"az":        subnet.az,
	})
	logger.G(ctx).Debug("Beginning GC of excess branch ENIs")
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: subnet.accountID, Region: subnet.region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	ec2client := ec2.New(session.Session)
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
DELETE
FROM branch_enis
WHERE branch_eni IN
    (SELECT branch_eni
     FROM branch_enis
     WHERE branch_eni NOT IN
         (SELECT branch_eni
          FROM branch_eni_attachments)
       AND subnet_id = $1
     ORDER BY id DESC
     LIMIT 1
     OFFSET $2) RETURNING branch_eni
`, subnet.subnetID, warmPoolPerSubnet)
	var branchENI string
	err = row.Scan(&branchENI)
	if err == sql.ErrNoRows {
		logger.G(ctx).Info("Did not find branch ENI to delete")
		return false, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot scan branch ENI to delete")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	iface, err := session.GetNetworkInterfaceByID(ctx, branchENI, 500*time.Millisecond)
	if err != nil {
		err = errors.Wrap(err, "Could not describe network interface")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	if l := len(iface.Ipv6Addresses); l > 0 {
		err = fmt.Errorf("Could not GC interface, had %d IPv6 addresses still assigned", l)
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}
	if l := len(iface.PrivateIpAddresses); l > 1 {
		err = fmt.Errorf("Could not GC interface, had %d IPv4 addresses still assigned", l)
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	logger.G(ctx).WithField("eni", branchENI).Info("Deleting excess ENI")
	_, err = ec2client.DeleteNetworkInterfaceWithContext(ctx, &ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(branchENI),
	})
	if err != nil {
		return false, ec2wrapper.HandleEC2Error(err, span)
	}
	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}
	return true, nil
}
