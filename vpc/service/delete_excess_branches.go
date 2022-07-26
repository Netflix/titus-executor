package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/metrics"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
)

const (
	defaultWarmPoolPerSubnet     = 50
	timeBetweenErrors            = 10 * time.Second
	timeBetweenNoDeletions       = 2 * time.Minute
	timeBetweenDeletions         = 5 * time.Second
	deleteExcessBranchENITimeout = 30 * time.Second
	minTimeExisting              = assignTimeout
)

func (vpcService *vpcService) getSubnets(ctx context.Context) ([]data.KeyedItem, error) {
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
SELECT subnets.id,
       subnets.az,
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

	ret := []data.KeyedItem{}
	for rows.Next() {
		var s data.Subnet
		err = rows.Scan(&s.ID, &s.Az, &s.VpcID, &s.AccountID, &s.SubnetID, &s.Cidr, &s.Region)
		if err != nil {
			return nil, err
		}
		ret = append(ret, &s)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return ret, nil
}

func (vpcService *vpcService) deleteExccessBranchesLoop(ctx context.Context, protoItem data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	subnet := protoItem.(*data.Subnet)
	for {
		var resetTime time.Duration
		ctx = logger.WithFields(ctx, map[string]interface{}{
			"region":    subnet.Region,
			"accountID": subnet.AccountID,
		})
		start := time.Now()
		branchesDeleted, err := vpcService.doDeleteExcessBranches(ctx, subnet)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to delete excess branches")
			stats.Record(ctx, metrics.ErrorDeleteExcessBranchENIsCount.M(1))
			resetTime = timeBetweenErrors
		} else {
			stats.Record(ctx, metrics.DeleteExcessBranchENIsLatency.M(time.Since(start).Milliseconds()))
			if branchesDeleted {
				resetTime = timeBetweenDeletions
			} else {
				resetTime = timeBetweenNoDeletions
			}
		}
		err = waitFor(ctx, resetTime)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) getWarmPoolSize(ctx context.Context, subnet *data.Subnet) (int, error) {
	ctx, span := trace.StartSpan(ctx, "getWarmPoolSize")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = fmt.Errorf("Could not start read only txn: %w", err)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	defer func() {
		_ = tx.Rollback()
	}()
	row := tx.QueryRowContext(ctx, "SELECT warm_pool_size FROM warm_pool_override WHERE subnet_id = $1", subnet.SubnetID)
	var warmPoolSize int
	err = row.Scan(&warmPoolSize)
	if err == sql.ErrNoRows {
		warmPoolSize = defaultWarmPoolPerSubnet
	} else if err != nil {
		err = fmt.Errorf("Could not query warm pool override for subnet %q: %w", subnet.SubnetID, err)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	if warmPoolSize <= 0 {
		err = fmt.Errorf("Warm pool size is not greater than 0: %d", warmPoolSize)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	err = tx.Commit()
	if err != nil {
		err = fmt.Errorf("Could not commit transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return 0, err
	}

	return warmPoolSize, nil
}

func (vpcService *vpcService) doDeleteExcessBranches(ctx context.Context, subnet *data.Subnet) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, deleteExcessBranchENITimeout)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doDeleteExcessBranches")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("subnet", subnet.SubnetID),
		trace.StringAttribute("accountID", subnet.AccountID),
		trace.StringAttribute("az", subnet.Az),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"subnet":    subnet.SubnetID,
		"accountID": subnet.AccountID,
		"az":        subnet.Az,
	})
	logger.G(ctx).Debug("Beginning GC of excess branch ENIs")

	warmPoolSize, err := vpcService.getWarmPoolSize(ctx, subnet)
	if err != nil {
		err = fmt.Errorf("Could not get warm pool size for subnet %q: %w", subnet.SubnetID, err)
		tracehelpers.SetStatus(err, span)
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: subnet.AccountID, Region: subnet.Region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	var branchENI string
	var fastTx *sql.Tx
	var serializationFailuresGetENI int64
get_eni:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = vpcService.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  true,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot start serialized, readonly database transaction")
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	row := fastTx.QueryRowContext(ctx, `
     SELECT branch_eni
     FROM branch_enis
     WHERE branch_eni NOT IN
         (SELECT branch_eni
          FROM branch_eni_attachments WHERE state = 'attached' OR state = 'attaching' OR state = 'unattaching')
       AND subnet_id = $1
       AND created_at < now() - ($3 * interval '1 sec')
     ORDER BY last_assigned_to ASC, id DESC
     LIMIT 1
     OFFSET $2
`, subnet.SubnetID, warmPoolSize, minTimeExisting.Seconds())
	err = row.Scan(&branchENI)
	if vpcerrors.IsSerializationFailure(err) {
		serializationFailuresGetENI++
		goto get_eni
	}
	if err == sql.ErrNoRows {
		logger.G(ctx).Info("Did not find branch ENI to delete")
		return false, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot scan branch ENI to delete")
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	err = fastTx.Commit()
	if vpcerrors.IsSerializationFailure(err) {
		serializationFailuresGetENI++
		goto get_eni
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot commit read only transaction to get ENI to delete")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	span.AddAttributes(
		trace.StringAttribute("eni", branchENI),
		trace.Int64Attribute("serializationFailuresGetENI", serializationFailuresGetENI),
	)

	ctx = logger.WithField(ctx, "eni", branchENI)
	iface, err := session.GetNetworkInterfaceByID(ctx, branchENI, 500*time.Millisecond)
	if err != nil {
		err = errors.Wrap(err, "Could not describe network interface")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	if len(iface.Ipv6Prefixes) > 0 {
		// We currently need 1 IP to work around the PD ND / RA bug
		if len(iface.Ipv6Addresses) > 1 {
			err = fmt.Errorf("Could not GC interface, had %d IPv6 addresses, %d IPv6 Prefixes still assigned", len(iface.Ipv6Addresses), len(iface.Ipv6Prefixes))
		}
	} else if len(iface.Ipv6Addresses) > 0 {
		err = fmt.Errorf("Could not GC interface, had %d IPv6 addresses,", len(iface.Ipv6Addresses))
	}

	if err != nil {
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	if l := len(iface.PrivateIpAddresses); l > 1 {
		err = fmt.Errorf("Could not GC interface, had %d IPv4 addresses still assigned", l)
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	// TODO: Handle the not found case
	logger.G(ctx).Info("Deleting excess ENI")

	var result sql.Result
	var deleteENISerializationErrors, rowsAffected int64
delete_eni:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Unable to start transaction to delete branch ENI from table")
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	result, err = fastTx.ExecContext(ctx, `
DELETE
FROM branch_enis
WHERE branch_eni = $1
  AND branch_enis.branch_eni NOT IN
    (SELECT branch_eni
     FROM branch_eni_attachments
     WHERE state = 'attached'
       OR state = 'attaching'
       OR state = 'unattaching')
`, branchENI)
	if vpcerrors.IsSerializationFailure(err) {
		deleteENISerializationErrors++
		goto delete_eni
	}
	if err != nil {
		err = errors.Wrap(err, "Could not delete ENI from database")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	rowsAffected, err = result.RowsAffected()
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch rows affected")
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	if rowsAffected != 1 {
		err = fmt.Errorf("Unexpected number of rows deleted %d, deleted indicative that the ENI %q was consumed", rowsAffected, branchENI)
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	err = fastTx.Commit()
	if vpcerrors.IsSerializationFailure(err) {
		deleteENISerializationErrors++
		goto delete_eni
	}
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction deleting ENIs")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: aws.String(branchENI),
	})
	if err != nil {
		awsErr := ec2wrapper.RetrieveEC2Error(err)
		if awsErr != nil && awsErr.Code() == ec2wrapper.InvalidNetworkInterfaceIDNotFound {
			logger.G(ctx).Info("Network interface was already deleted")
			return true, nil
		}
		logger.G(ctx).WithError(err).Error("Deleted (excess) branch ENI from database, but was unable to delete it from AWS; ENI leak")
		return false, ec2wrapper.HandleEC2Error(err, span)
	}

	return true, nil
}

func (vpcService *vpcService) deleteExcessBranchesLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "delete_excess_branches",
		itemLister: vpcService.getSubnets,
		workFunc:   vpcService.deleteExccessBranchesLoop,
	}
}
