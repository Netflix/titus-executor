package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

const (
	timeBetweenDetaches    = 5 * time.Second
	timeBetweenNoDetatches = time.Minute
	minTimeUnused          = time.Hour
)

type nilItem struct {
}

func (n *nilItem) key() string {
	return "nilitem"
}

func (n *nilItem) String() string {
	return "Nilitem{}"
}

func nilItemEnumerator(ctx context.Context) ([]keyedItem, error) {
	return []keyedItem{&nilItem{}}, nil
}

func (vpcService *vpcService) detatchUnusedBranchENILoop(ctx context.Context, protoItem keyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		resetTime, err := vpcService.doDetatchUnusedBranchENI(ctx)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to detach ENI")
		}
		err = waitFor(ctx, resetTime)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doDetatchUnusedBranchENI(ctx context.Context) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doDetatchUnusedBranchENI")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		span.SetStatus(traceStatusFromError(err))
		return 0, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT branch_eni_attachments.branch_eni,
       association_id,
       availability_zones.region,
       trunk_enis.account_id,
       COALESCE(
                  (SELECT last_used
                   FROM branch_eni_last_used
                   WHERE branch_eni = branch_enis.branch_eni), TIMESTAMP 'EPOCH') AS lu
FROM branch_eni_attachments
JOIN branch_enis ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
JOIN availability_zones ON trunk_enis.account_id = availability_zones.account_id
AND trunk_enis.az = availability_zones.zone_name
WHERE branch_eni_attachments.association_id NOT IN
    (SELECT branch_eni_association
     FROM assignments)
ORDER BY COALESCE(
                    (SELECT last_used
                     FROM branch_eni_last_used
                     WHERE branch_eni = branch_eni_attachments.branch_eni), TIMESTAMP 'EPOCH') ASC
LIMIT 1
FOR NO KEY
UPDATE OF branch_eni_attachments SKIP LOCKED
`)
	var branchENI, associationID, region, accountID string
	var lastUsed time.Time
	err = row.Scan(&branchENI, &associationID, &region, &accountID, &lastUsed)
	if err == sql.ErrNoRows {
		logger.G(ctx).Info("Did not find branch ENI to disassociate")
		return timeBetweenNoDetatches, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot scan branch ENI to delete")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}
	timeSinceLastUsed := time.Since(lastUsed)
	if timeSinceLastUsed < minTimeUnused {
		waitTime := minTimeUnused - timeSinceLastUsed
		return waitTime, nil
	}
	span.AddAttributes(trace.StringAttribute("eni", branchENI))

	logger.G(ctx).WithField("eni", branchENI).Info("Disassociating ENI")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		Region:    region,
		AccountID: accountID,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}

	err = vpcService.disassociateNetworkInterface(ctx, tx, session, associationID, false)
	if !errors.Is(err, &irrecoverableError{}) && !errors.Is(err, &persistentError{}) {
		err2 := tx.Commit()
		if err2 != nil {
			err2 = errors.Wrap(err2, "Could not commit transaction")
			span.SetStatus(traceStatusFromError(err2))
			return timeBetweenErrors, err2
		}
		logger.G(ctx).WithError(err).Error("Experienced error while trying to disassociate network interface")
		return timeBetweenErrors, nil
	} else if err != nil {
		err = errors.Wrap(err, "Cannot disassociate network interface")
		tracehelpers.SetStatus(err, span)
		return timeBetweenErrors, nil
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}
	return timeBetweenDetaches, nil
}
