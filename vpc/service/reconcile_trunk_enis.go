package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	timeBetweenTrunkENIReconcilation = time.Minute
)

func (vpcService *vpcService) reconcileTrunkENIsForRegionAccountLoop(ctx context.Context, protoItem data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*regionAccount)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"region":    item.region,
		"accountID": item.accountID,
	})

	for {
		err := vpcService.reconcileTrunkENIsForRegionAccount(ctx, item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to reconcile trunk ENIs")
		}
		err = waitFor(ctx, timeBetweenTrunkENIReconcilation)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) reconcileTrunkENIsForRegionAccount(ctx context.Context, account *regionAccount) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileTrunkENIsForRegionAccount")
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

	// Reconciling AWS -> DB
	// 1. Find all trunk ENIs in AWS
	// 2. If a trunk ENI has delete on terminate set, unset it
	// 3. If it is attached, insert it into the database (or set deleting to = f)
	// 4. If it is not attached run the "safe" delete operation on it [if this fails, hopefully on the next reconcilation something good will happen?]
	//
	// Why do we do multi-phasic deletes, and not just delete from our db and then delete in AWS?
	//
	// Play out this example:
	// 1. I create and attach the interface
	// 2. Reconcilation runs and gets an eventual consistent reply from AWS saying that the interface is not attached
	// 3. We delete it from the db entirely (no tombstone)
	// 4. If we used this branch ENI for any associations, we just blew away those associations
	//
	// Another aspect is in order to see if a network interface really does not exist, we have to do some intrusive
	// (expensive) probing. I'd rather not do that
	//
	//
	// Reconcilation of DB -> AWS [How do we deal with ENIs which got deleted outside of titus]
	// 1. If the ENI was not in the describe call above
	// 2. If there is a tombstone, then delete the row from the database table, and all the associations associated with it
	// 3. If there is not a tombstone, we try and ModifyNetworkInterfaceAttribute to see if it exists. If it exists, we leave it alone,
	//    and hope it comes back later, if not, blow it away from the db, otherwise hardDelete
	//
	// Also, unmark all tombstones > 24 hours old
	//

	logger.G(ctx).Info("Beginning reconcilation of trunk ENIs")

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpcService.config.TrunkNetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{account.accountID}),
			},
		},
		MaxResults: aws.Int64(1000),
	}

	networkInterfaces := []*ec2.NetworkInterface{}
	for {
		describeNetworkInterfacesOutput, err := session.DescribeNetworkInterfaces(ctx, describeNetworkInterfacesInput)
		if err != nil {
			err = errors.Wrap(err, "Cannot describe network interfaces")
			tracehelpers.SetStatus(err, span)
			return err
		}

		networkInterfaces = append(networkInterfaces, describeNetworkInterfacesOutput.NetworkInterfaces...)

		if describeNetworkInterfacesOutput.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}

	enis := sets.NewString()

	for idx := range networkInterfaces {
		ni := networkInterfaces[idx]
		networkInterfaceID := aws.StringValue(ni.NetworkInterfaceId)
		enis.Insert(networkInterfaceID)
		ctx2 := logger.WithField(ctx, "eni", networkInterfaceID)
		if ni.Attachment != nil {
			err = vpcService.reconcileAttachedTrunkENI(ctx2, session, ni)
			if err != nil {
				logger.G(ctx2).WithError(err).Error("Cannot reconcile attached trunk ENI")
			}
		} else {
			err = vpcService.reconcileUnattachedTrunkENI(ctx2, session, ni)
			if err != nil {
				logger.G(ctx2).WithError(err).Error("Cannot reconcile unattached trunk ENI")
			}
		}
	}

	err = vpcService.reconcileTrunkENIsForRegionAccountInDatabase(ctx, account, session, enis)
	tracehelpers.SetStatus(err, span)

	return err
}

func (vpcService *vpcService) reconcileTrunkENIsForRegionAccountInDatabase(ctx context.Context, account *regionAccount, session *ec2wrapper.EC2Session, enis sets.String) error {
	if enis.Len() == 0 {
		return nil
	}

	ctx, span := trace.StartSpan(ctx, "reconcileTrunkENIsForRegionAccountInDatabase")
	defer span.End()

	databaseOrphanedTrunkENIs, err := vpcService.getDatabaseOrphanedTrunkENIs(ctx, account, enis)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Cannot find orphaned ENIs")
	}

	logger.G(ctx).WithField("enis", databaseOrphanedTrunkENIs).Debug("Found orphaned ENIs")

	for _, eni := range databaseOrphanedTrunkENIs.UnsortedList() {
		ctx2 := logger.WithField(ctx, "eni", eni)
		err = vpcService.reconcileOrphanedTrunkENI(ctx2, session, eni)
		if err != nil {
			logger.G(ctx2).WithError(err).Error("Cannot reconcile orphaned ENI")
		}
	}

	return nil
}

func (vpcService *vpcService) reconcileOrphanedTrunkENI(ctx context.Context, session *ec2wrapper.EC2Session, eni string) error {
	ctx, span := trace.StartSpan(ctx, "reconcileOrphanedTrunkENI")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", eni))

	exists, tombstone, err := vpcService.getTrunkNetworkInterfaceTombstone(ctx, eni)
	if err != nil {
		err = errors.Wrap(err, "Could not get tombstone for network interface")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if !exists {
		err = fmt.Errorf("Oprhaned ENI %s could not be found in the database", eni)
		tracehelpers.SetStatus(err, span)
		return err
	}

	if tombstone != nil {
		logger.G(ctx).Info("Hard deleting ENI, as tombstone is set, meaning that (we may) have tried deleting it in the past")
		err = vpcService.hardDeleteTrunkInterface(ctx, eni)
		if err != nil {
			err = errors.Wrap(err, "Could not hard delete ENI")
			tracehelpers.SetStatus(err, span)
		}
		return err
	}

	eniExists, err := doesENIExist(ctx, session, eni, vpcService.config.TrunkNetworkInterfaceDescription)
	if err != nil {
		err = errors.Wrap(err, "Could not find out if branch ENI exists")
		return ec2wrapper.HandleEC2Error(err, span)
	}

	if eniExists {
		logger.G(ctx).Warning("ENI actually exists in AWS according to modify call")
		return nil
	}
	logger.G(ctx).Info("Hard deleting ENI, as could not find it in AWS")
	err = vpcService.hardDeleteTrunkInterface(ctx, eni)
	if err != nil {
		err = errors.Wrap(err, "Could not hard delete ENI")
		return ec2wrapper.HandleEC2Error(err, span)
	}

	return nil
}

func (vpcService *vpcService) getDatabaseOrphanedTrunkENIs(ctx context.Context, account *regionAccount, enis sets.String) (sets.String, error) {
	ctx, span := trace.StartSpan(ctx, "getDatabaseOrphanedTrunkENIs")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx,
		`SELECT trunk_eni FROM trunk_enis WHERE trunk_eni != all($1) AND region = $2 AND account_id = $3`,
		pq.Array(enis.UnsortedList()), account.region, account.accountID)
	if err != nil {
		err = errors.Wrap(err, "Could not query for orphaned trunk ENIs")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	orphanedENIs := sets.NewString()
	for rows.Next() {
		var trunkENI string
		err = rows.Scan(&trunkENI)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan trunk ENI")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		orphanedENIs.Insert(trunkENI)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return orphanedENIs, nil
}

func (vpcService *vpcService) reconcileAttachedTrunkENI(ctx context.Context, session *ec2wrapper.EC2Session, networkInterface *ec2.NetworkInterface) error {
	ctx, span := trace.StartSpan(ctx, "reconcileAttachedTrunkENI")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(networkInterface.NetworkInterfaceId)))

	if aws.BoolValue(networkInterface.Attachment.DeleteOnTermination) {
		logger.G(ctx).WithField("attachment", networkInterface.Attachment).Info("Modifying attachment not to delete on termination")
		_, err := session.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
			Attachment: &ec2.NetworkInterfaceAttachmentChanges{
				AttachmentId:        networkInterface.Attachment.AttachmentId,
				DeleteOnTermination: aws.Bool(false),
			},
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
		})
		if err != nil {
			err = errors.Wrap(err, "Cannot turn delete on terminate off")
			tracehelpers.SetStatus(err, span)
			return err
		}
	}
	// Make sure the trunk ENI is in the database.
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Generation is only set at ENI creation time, not updated
	err = insertTrunkENIIntoDB(ctx, tx, networkInterface, 0)
	if err != nil {
		err = errors.Wrap(err, "Cannot update trunk enis")
		tracehelpers.SetStatus(err, span)
		return err
	}
	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	return nil

}

func (vpcService *vpcService) reconcileUnattachedTrunkENI(ctx context.Context, session *ec2wrapper.EC2Session, networkInterface *ec2.NetworkInterface) error {
	ctx, span := trace.StartSpan(ctx, "reconcileUnattachedTrunkENI")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(networkInterface.NetworkInterfaceId)))

	exists, tombstone, err := vpcService.getTrunkNetworkInterfaceTombstone(ctx, aws.StringValue(networkInterface.NetworkInterfaceId))
	if err != nil {
		err = errors.Wrap(err, "Cannot get network interface tombstone")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if !exists {
		logger.G(ctx).Info("Found unattached branch ENI not in database, attempting to delete")
		_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: networkInterface.NetworkInterfaceId})
		if err != nil {
			err = errors.Wrap(err, "Could not delete dangling trunk interface")
		}
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).Info("Found unattached branch ENI, attempting to delete gracefully")

	if tombstone != nil {
		logger.G(ctx).WithField("tombstone", tombstone).Info("Found tombstoned ENI on reconcilation, likely leak")
	}

	err = vpcService.deleteTrunkInterface(ctx, session, aws.StringValue(networkInterface.NetworkInterfaceId))
	if err != nil {
		logger.G(ctx).WithError(err).Error("Cannot delete unattached network interface")
	}

	return nil
}

func (vpcService *vpcService) reconcileTrunkENIsLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "reconcile_trunk_enis",
		itemLister: vpcService.getTrunkENIRegionAccounts,
		workFunc:   vpcService.reconcileTrunkENIsForRegionAccountLoop,
	}
}
