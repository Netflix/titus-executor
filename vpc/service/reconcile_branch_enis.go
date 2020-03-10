package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	timeBetweenBranchENIReconcilation = time.Minute
)

func (vpcService *vpcService) reconcileBranchENILoop(ctx context.Context, protoItem keyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*regionAccount)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"region":    item.region,
		"accountID": item.accountID,
	})
	for {
		err := vpcService.reconcileBranchENIsForRegionAccount(ctx, item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to reconcile branch ENIs")
		}
		err = waitFor(ctx, timeBetweenBranchENIReconcilation)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) reconcileBranchENIsForRegionAccount(ctx context.Context, account *regionAccount) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIsForRegionAccount")
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

	logger.G(ctx).Info("Beginning reconcilation of branch ENIs")

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpc.BranchNetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{account.accountID}),
			},
		},
		MaxResults: aws.Int64(1000),
	}

	errGroup, groupCtx := errgroup.WithContext(ctx)
	networkInterfacesToCheckChan := make(chan *ec2.NetworkInterface, 1000)
	enis := sets.NewString()

	lock := &sync.Mutex{}
	networkInterfacesToRecheck := []*ec2.NetworkInterface{}

	for i := 0; i < 10; i++ {
		errGroup.Go(func() error {
			for {
				select {
				case ni, ok := <-networkInterfacesToCheckChan:
					if !ok {
						return nil
					}
					ctx2 := logger.WithField(groupCtx, "eni", aws.StringValue(ni.NetworkInterfaceId))
					recheck, err := vpcService.reconcileBranchENI(ctx2, session, ni)
					if err != nil {
						logger.G(ctx2).WithError(err).Error("Was unable to reconcile branch ENI")
					} else if recheck {
						lock.Lock()
						networkInterfacesToRecheck = append(networkInterfacesToRecheck, ni)
						lock.Unlock()
					}
				case <-groupCtx.Done():
					return groupCtx.Err()
				}
			}
		})
	}

	for {
		describeNetworkInterfacesOutput, err := session.DescribeNetworkInterfaces(groupCtx, describeNetworkInterfacesInput)
		if err != nil {
			close(networkInterfacesToCheckChan)
			logger.G(groupCtx).WithError(err).Error("Could not describe network interfaces")
			return ec2wrapper.HandleEC2Error(err, span)
		}

		for idx := range describeNetworkInterfacesOutput.NetworkInterfaces {
			ni := describeNetworkInterfacesOutput.NetworkInterfaces[idx]
			networkInterfaceID := aws.StringValue(ni.NetworkInterfaceId)
			enis.Insert(networkInterfaceID)
			networkInterfacesToCheckChan <- ni
		}

		if describeNetworkInterfacesOutput.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}
	close(networkInterfacesToCheckChan)

	err = errGroup.Wait()
	if err != nil {
		err = errors.Wrap(err, "Unable to check network interfaces")
		tracehelpers.SetStatus(err, span)
		return err
	}
	lock.Lock()

	recheckTime := time.NewTimer(deleteExcessBranchENITimeout + time.Second)
	defer recheckTime.Stop()

	orphanedENIs, err := vpcService.getDatabaseOrphanedBranchENIs(ctx, account, enis)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	for _, eni := range orphanedENIs.UnsortedList() {
		ctx2 := logger.WithField(ctx, "eni", eni)
		err = vpcService.reconcileOrphanedBranchENI(ctx2, session, eni)
		if err != nil {
			logger.G(ctx2).WithError(err).Error("Could not reconcile orphaned branch ENI")
		}
	}

	if l := len(networkInterfacesToRecheck); l > 0 {
		logger.G(ctx).Infof("Have %d interface to recheck", l)
		select {
		case <-recheckTime.C:
		case <-ctx.Done():
			tracehelpers.SetStatus(ctx.Err(), span)
			return ctx.Err()
		}
		logger.G(ctx).Info("Rechecking interfaces")
		for idx := range networkInterfacesToRecheck {
			ni := networkInterfacesToRecheck[idx]
			networkInterfaceID := aws.StringValue(ni.NetworkInterfaceId)
			ctx2 := logger.WithField(ctx, "eni", networkInterfaceID)
			err = vpcService.reconcileBranchENIMissingInDatabase(ctx2, session, ni)
			if err != nil {
				logger.G(ctx2).WithError(err).Error("Was unable to recheck branch ENI")
			}
		}
	}

	return nil
}

func (vpcService *vpcService) reconcileOrphanedBranchENI(ctx context.Context, session *ec2wrapper.EC2Session, eni string) error {
	ctx, span := trace.StartSpan(ctx, "reconcileOrphanedBranchENI")
	defer span.End()

	eniExists, err := doesENIExist(ctx, session, eni, vpc.BranchNetworkInterfaceDescription)
	if err != nil {
		err = errors.Wrap(err, "Could not find out if branch ENI exists")
		return ec2wrapper.HandleEC2Error(err, span)
	}
	if eniExists {
		logger.G(ctx).Info("ENI exists in AWS, but didn't exist in describe call")
		return nil
	}

	logger.G(ctx).Warning("Deleting Branch ENI from database, as could not find it in AWS")
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = tx.ExecContext(ctx, "DELETE FROM branch_enis WHERE branch_eni = $1", eni)
	if err != nil {
		err = errors.Wrap(err, "Could not delete branch ENI from database")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) getDatabaseOrphanedBranchENIs(ctx context.Context, account *regionAccount, enis sets.String) (sets.String, error) { //nolint:dupl
	ctx, span := trace.StartSpan(ctx, "getDatabaseOrphanedBranchENIs")
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
		`
SELECT branch_eni
FROM branch_enis
WHERE
    (SELECT region
     FROM availability_zones
     WHERE zone_name = branch_enis.az
       AND account_id = branch_enis.account_id) = $1
  AND account_id = $2
  AND branch_eni != all($3)
`,
		account.region, account.accountID, pq.Array(enis.UnsortedList()))
	if err != nil {
		err = errors.Wrap(err, "Could not query for orphaned branch ENIs")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	orphanedENIs := sets.NewString()
	for rows.Next() {
		var branchENI string
		err = rows.Scan(&branchENI)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan branch ENI")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		orphanedENIs.Insert(branchENI)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return orphanedENIs, nil
}

func (vpcService *vpcService) reconcileBranchENI(ctx context.Context, session *ec2wrapper.EC2Session, networkInterface *ec2.NetworkInterface) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENI")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "SELECT security_groups FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", aws.StringValue(networkInterface.NetworkInterfaceId))
	var dbSecurityGroups []string
	err = row.Scan(pq.Array(&dbSecurityGroups))
	if err == sql.ErrNoRows {
		// This means the branch ENI was in AWS, but not in the database
		// This could mean:
		// 1. The interface is being deleted by the deleter
		// 2. The interface was "orphaned" (created, but the txn didn't commit successfully)
		//
		// Without the "complicated" tombstoning behaviour we do for trunk ENIs, we just check again if it exists in a little bit.
		logger.G(ctx).Info("ENI not found in database, marking ENI to be rechecked, and potentially inserted into the database")
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction (no writes performed)")
			tracehelpers.SetStatus(err, span)
			return false, err
		}
		return true, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Could not scan row")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	networkInterfaceSecurityGroups := make([]string, len(networkInterface.Groups))
	for idx := range networkInterface.Groups {
		networkInterfaceSecurityGroups[idx] = aws.StringValue(networkInterface.Groups[idx].GroupId)
	}
	sort.Strings(networkInterfaceSecurityGroups)
	networkInterfaceSecurityGroupsSet := sets.NewString(networkInterfaceSecurityGroups...)

	span.AddAttributes(trace.StringAttribute("networkInterfaceSecurityGroups", fmt.Sprintf("%+v", networkInterfaceSecurityGroups)))

	// We need to update the security groups in the database
	if len(dbSecurityGroups) == 0 {
		logger.G(ctx).Info("Security groups empty in database, updating from AWS")
		_, err = tx.ExecContext(ctx,
			"UPDATE branch_enis SET security_groups = $1 WHERE branch_eni = $2",
			pq.Array(networkInterfaceSecurityGroups), aws.StringValue(networkInterface.NetworkInterfaceId))
		if err != nil {
			err = errors.Wrap(err, "Could not update security groups in database")
			tracehelpers.SetStatus(err, span)
			return false, err
		}
	} else if dbSecurityGroupsSet := sets.NewString(dbSecurityGroups...); !dbSecurityGroupsSet.Equal(networkInterfaceSecurityGroupsSet) {
		span.AddAttributes(trace.StringAttribute("dbSecurityGroups", fmt.Sprintf("%+v", dbSecurityGroups)))
		// We need to update the security groups in AWS
		logger.G(ctx).
			WithField("dbSecurityGroups", dbSecurityGroups).WithField("networkInterfaceSecurityGroups", networkInterfaceSecurityGroups).
			Warn("Security groups differ between database and AWS, updating network interface in AWS with security groups from database")
		_, err := session.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
			Groups:             aws.StringSlice(dbSecurityGroups),
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
		})

		awsErr := ec2wrapper.RetrieveEC2Error(err)
		if awsErr != nil {
			logger.G(ctx).WithError(err).Error("Unable to update security groups on interface from database due to AWS error")
			if awsErr.Code() == ec2wrapper.InvalidGroupNotFound {
				// The security groups in the database are wrong
				// We can just update them based on what the security groups are from the ENI
				logger.G(ctx).Info("Security groups incorrect in database, updating from AWS")
				_, err = tx.ExecContext(ctx,
					"UPDATE branch_enis SET security_groups = $1 WHERE branch_eni = $2",
					pq.Array(networkInterfaceSecurityGroups), aws.StringValue(networkInterface.NetworkInterfaceId))
				if err != nil {
					err = errors.Wrap(err, "Could not update security groups in database")
					tracehelpers.SetStatus(err, span)
					return false, err
				}
			} else {
				err = errors.Wrap(err, "Could not update security groups via modify network interface")
				return false, ec2wrapper.HandleEC2Error(err, span)
			}
		} else if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to update security groups on interface from database")
			// Something weird has happened
			tracehelpers.SetStatus(err, span)
			return false, err
		}
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could commit transaction")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	return false, nil
}

func (vpcService *vpcService) reconcileBranchENIMissingInDatabase(ctx context.Context, session *ec2wrapper.EC2Session, networkInterface *ec2.NetworkInterface) error {
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENIMissingInDatabase")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	logger.G(ctx).WithField("networkInterface", networkInterface)
	ctx = logger.WithField(ctx, "eni", aws.StringValue(networkInterface.NetworkInterfaceId))
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(networkInterface.NetworkInterfaceId)))

	// Let's do a simple describe first. We cannot use a batch describe,
	// because if one interface comes back not found in a batch describe,
	// it fails the full thing
	output, err := session.DescribeNetworkInterfaces(ctx, ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{networkInterface.NetworkInterfaceId},
	})
	if err != nil {
		awsErr := ec2wrapper.RetrieveEC2Error(err)
		if awsErr != nil {
			if awsErr.Code() == ec2wrapper.InvalidNetworkInterfaceIDNotFound {
				logger.G(ctx).Info("Interface was deleted in AWS, all is well")
				return nil
			}
			logger.G(ctx).WithError(err).Error("Received unexpected error from AWS")
			return ec2wrapper.HandleEC2Error(err, span)

		}
		logger.G(ctx).WithError(err).Error("Experienced error unrelated to AWS")
		tracehelpers.SetStatus(err, span)
		return err
	}

	eniExists, err := doesENIExist(ctx, session, aws.StringValue(networkInterface.NetworkInterfaceId), vpc.BranchNetworkInterfaceDescription)
	if err != nil {
		err = errors.Wrap(err, "Could not determine if ENI exists")
		return ec2wrapper.HandleEC2Error(err, span)
	}
	if !eniExists {
		logger.G(ctx).Warn("ENI does not exist, but is returning in describe calls")
		return nil
	}

	logger.G(ctx).Info("ENI actually exists, inserting it back into database")
	// This interface still exists, which means it's probably a leak. Time to insert it into the DB.
	iface := output.NetworkInterfaces[0]

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	err = insertBranchENIIntoDB(ctx, tx, iface)
	if err != nil {
		err = errors.Wrap(err, "Could not insert branch ENI into database")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) reconcileBranchENIsLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "reconcile_branch_enis",
		itemLister: vpcService.getBranchENIRegionAccounts,
		workFunc:   vpcService.reconcileBranchENILoop,
	}
}
