package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/metrics"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"go.opencensus.io/trace"
)

const (
	timeBetweenDetaches    = 5 * time.Second
	timeBetweenNoDetatches = time.Minute
	minTimeUnused          = time.Hour
	minTimeAttached        = assignTimeout
	contextTimeout         = 10 * time.Minute
)

func nilItemEnumerator(ctx context.Context) ([]data.KeyedItem, error) {
	return []data.KeyedItem{&data.NilItem{}}, nil
}

func (vpcService *vpcService) detatchUnusedBranchENILoop(ctx context.Context, protoItem data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*data.Subnet)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"subnet":    item.SubnetID,
		"accountID": item.AccountID,
		"az":        item.Az,
	})
	for {
		resetTime, err := vpcService.doDetatchUnusedBranchENI(ctx, item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to detach unused branch ENIs")
			stats.Record(ctx, metrics.ErrorDetachUnusedBranchENIsCount.M(1))
		} else {
			logger.G(ctx).WithField("resetTime", resetTime).Debug("Waiting to recheck")
		}
		err = waitFor(ctx, resetTime)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doDetatchUnusedBranchENI(ctx context.Context, subnet *data.Subnet) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, contextTimeout)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doDetatchUnusedBranchENI")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return timeBetweenErrors, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT branch_eni_attachments.branch_eni,
       association_id,
       availability_zones.region,
       trunk_enis.account_id
FROM branch_eni_attachments
JOIN branch_enis ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
JOIN availability_zones ON trunk_enis.account_id = availability_zones.account_id
AND trunk_enis.az = availability_zones.zone_name
WHERE NOT EXISTS (SELECT branch_eni_association from assignments where branch_eni_attachments.association_id = assignments.branch_eni_association)
	AND branch_eni_attachments.attachment_completed_at < now() - ($1 * interval '1 sec')
    AND branch_eni_attachments.state = 'attached'
    AND branch_enis.last_assigned_to < now() - ($2 * interval '1 sec')
	AND branch_enis.last_used < now() - ($2 * interval '1 sec')
	AND branch_enis.subnet_id = $3
ORDER BY COALESCE(branch_enis.last_assigned_to, TIMESTAMP 'EPOCH') ASC
LIMIT 1
`, minTimeAttached.Seconds(), minTimeUnused.Seconds(), subnet.SubnetID)
	var branchENI, associationID, region, accountID string
	err = row.Scan(&branchENI, &associationID, &region, &accountID)
	if err == sql.ErrNoRows {
		logger.G(ctx).Info("Did not find branch ENI to disassociate")
		return timeBetweenNoDetatches, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot scan branch ENI to delete")
		tracehelpers.SetStatus(err, span)
		return timeBetweenErrors, err
	}
	span.AddAttributes(trace.StringAttribute("eni", branchENI))

	logger.G(ctx).WithField("eni", branchENI).Info("Disassociating ENI")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		Region:    region,
		AccountID: accountID,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not get AWS session")
		tracehelpers.SetStatus(err, span)
		return timeBetweenErrors, err
	}

	err = vpcService.disassociateNetworkInterface(ctx, tx, session, associationID, false)
	if err != nil {
		if errors.Is(err, &vpcerrors.IrrecoverableError{}) || vpcerrors.IsPersistentError(err) {
			err2 := tx.Commit()
			if err2 != nil {
				err2 = errors.Wrap(err2, "Could not commit transaction during irrecoverableError / persistentError")
				tracehelpers.SetStatus(err, span)
				return timeBetweenErrors, err2
			}
		}
		err = errors.Wrap(err, "Cannot disassociate network interface")
		logger.G(ctx).WithError(err).Error("Experienced error while trying to disassociate network interface")
		tracehelpers.SetStatus(err, span)
		return timeBetweenErrors, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return timeBetweenErrors, err
	}
	return timeBetweenDetaches, nil
}
