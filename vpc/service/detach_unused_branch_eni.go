package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
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

func (vpcService *vpcService) detatchUnusedBranchENILoop(ctx context.Context, protoItem keyedItem) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		resetTime, err := vpcService.doDetatchUnusedBranchENI(ctx)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to detach ENI")
		}
		err = waitFor(ctx, resetTime)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Terminating loop")
			return
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
SELECT branch_enis.branch_eni,
       branch_eni_attachments.association_id,
       availability_zones.region,
       trunk_enis.account_id,
       COALESCE(
                  (SELECT last_used
                   FROM branch_eni_last_used
                   WHERE branch_eni = branch_enis.branch_eni), TIMESTAMP 'EPOCH') AS lu
FROM branch_enis
JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
JOIN availability_zones ON trunk_enis.account_id = availability_zones.account_id AND trunk_enis.az = availability_zones.zone_name
WHERE branch_eni_attachments.association_id NOT IN
    (SELECT branch_eni_association
     FROM assignments)
	AND attachment_generation = 3
ORDER BY lu ASC
LIMIT 1
FOR
UPDATE OF branch_enis,
          branch_eni_attachments

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

	// We could fetch the row ID if we wanted to be more efficient here, but this works fine for now
	// as there is an index on the association ID
	_, err = tx.ExecContext(ctx, "DELETE FROM branch_eni_attachments WHERE association_id = $1", associationID)
	if err != nil {
		err = errors.Wrap(err, "Could not delete association from database")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		Region:    region,
		AccountID: accountID,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}
	ec2client := ec2.New(session.Session)
	_, err = ec2client.DisassociateTrunkInterfaceWithContext(ctx, &ec2.DisassociateTrunkInterfaceInput{
		AssociationId: aws.String(associationID),
	})
	if err != nil {
		err = errors.Wrap(err, "Could not disassociate branch ENI")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}
	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return timeBetweenErrors, err
	}
	return timeBetweenDetaches, nil
}
