package service

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	timeBetweenBranchENIReconcilation = time.Minute
)

func (vpcService *vpcService) reconcileBranchENILoop(ctx context.Context, protoItem data.KeyedItem) error {
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
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).Info("Beginning reconcilation of branch ENIs")

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpcService.config.BranchNetworkInterfaceDescription}),
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

	eniExists, err := doesENIExist(ctx, session, eni, vpcService.config.BranchNetworkInterfaceDescription)
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

func (vpcService *vpcService) reconcileBranchENI(ctx context.Context, session *ec2wrapper.EC2Session, networkInterface *ec2.NetworkInterface) (bool, error) { // nolint:gocyclo
	ctx, span := trace.StartSpan(ctx, "reconcileBranchENI")
	defer span.End()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	branch := aws.StringValue(networkInterface.NetworkInterfaceId)
	span.AddAttributes(trace.StringAttribute("branch", branch))

	var fastTx *sql.Tx
	var err error
	var serializationErrors int64
	var rows *sql.Rows
	var assignments []string
	var state, associationID string

retry:
	assignments = []string{}
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return false, err
	}
	defer func(tx *sql.Tx) {
		_ = tx.Rollback()
	}(fastTx)

	row := fastTx.QueryRowContext(ctx, "SELECT security_groups, dirty_security_groups FROM branch_enis WHERE branch_eni = $1", branch)
	var dbSecurityGroups []string
	var dirtySecurityGroups bool
	err = row.Scan(pq.Array(&dbSecurityGroups), &dirtySecurityGroups)
	if vpcerrors.IsSerializationFailure(err) {
		serializationErrors++
		goto retry
	}

	if err == sql.ErrNoRows {
		// This means the branch ENI was in AWS, but not in the database
		// This could mean:
		// 1. The interface is being deleted by the deleter
		// 2. The interface was "orphaned" (created, but the txn didn't commit successfully)
		//
		// Without the "complicated" tombstoning behaviour we do for trunk ENIs, we just check again if it exists in a little bit.
		logger.G(ctx).Info("ENI not found in database, marking ENI to be rechecked, and potentially inserted into the database")
		err = fastTx.Commit()
		if vpcerrors.IsSerializationFailure(err) {
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Could not commit transaction")
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

	span.AddAttributes(trace.StringAttribute("networkInterfaceSecurityGroups", fmt.Sprintf("%+v", networkInterfaceSecurityGroups)))

	// Should we try to update the security groups from the database to the network interface in AWS. NO.
	securityGroupsMatch := sets.NewString(dbSecurityGroups...).Equal(sets.NewString(networkInterfaceSecurityGroups...))
	if securityGroupsMatch {
		err = fastTx.Commit()
		if vpcerrors.IsSerializationFailure(err) {
			serializationErrors++
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction")
			tracehelpers.SetStatus(err, span)
			return false, err
		}
		return false, nil
	} else if !dirtySecurityGroups {
		_, err = fastTx.ExecContext(ctx, "UPDATE branch_enis SET dirty_security_groups = true WHERE branch_eni = $1", branch)
		if vpcerrors.IsSerializationFailure(err) {
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Cannot mark current security groups as dirty")
			tracehelpers.SetStatus(err, span)
			return false, err
		}
	}

	row = fastTx.QueryRowContext(ctx, "SELECT state, association_id FROM branch_eni_attachments WHERE branch_eni = $1 AND (state = 'attaching' OR state = 'attached' OR state = 'unattaching')", branch)
	err = row.Scan(&state, &associationID)
	if vpcerrors.IsSerializationFailure(err) {
		goto retry
	}
	if err == sql.ErrNoRows {
		state = ""
	} else if err != nil {
		err = errors.Wrap(err, "Cannot query state of branchENI")
		tracehelpers.SetStatus(err, span)
		return false, err
	} else {
		ctx = logger.WithField(ctx, "state", state)
		rows, err = fastTx.QueryContext(ctx, "SELECT assignment_id FROM assignments WHERE branch_eni_association = $1", associationID)
		if vpcerrors.IsSerializationFailure(err) {
			goto retry
		}
		if err != nil {
			err = errors.Wrap(err, "Cannot fetch current assignments on branch ENI")
			tracehelpers.SetStatus(err, span)
			return false, err
		}
		for rows.Next() {
			var assignmentID string
			err = rows.Scan(&assignmentID)
			if err != nil {
				err = errors.Wrap(err, "Cannot scan assignment ID")
				tracehelpers.SetStatus(err, span)
				return false, err
			}
			assignments = append(assignments, assignmentID)
		}
	}

	err = fastTx.Commit()
	if vpcerrors.IsSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot commit current transaction")
		tracehelpers.SetStatus(err, span)
		return false, err
	}

	networkInterfaceStatus := aws.StringValue(networkInterface.Status)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"networkInterfaceStatus":         networkInterfaceStatus,
		"branch":                         branch,
		"dirtySecurityGroups":            dirtySecurityGroups,
		"networkInterfaceSecurityGroups": networkInterfaceSecurityGroups,
		"dbSecurityGroups":               dbSecurityGroups,
		"assignments":                    assignments,
		// Turns out counting is hard for some databases
		"assignmentCount": len(assignments),
	})

	span.AddAttributes(
		trace.StringAttribute("networkInterfaceStatus", networkInterfaceStatus),
		trace.StringAttribute("branch", networkInterfaceStatus),
		trace.BoolAttribute("dirtySecurityGroups", dirtySecurityGroups),
		trace.StringAttribute("networkInterfaceSecurityGroups", fmt.Sprint(networkInterfaceSecurityGroups)),
		trace.StringAttribute("dbSecurityGroups", fmt.Sprint(dbSecurityGroups)),
		trace.Int64Attribute("assignmentCount", int64(len(assignments))),
	)

	// If it's not used, then it doesn't really matter. The code which does the allocations will "fix it"
	if len(assignments) == 0 {
		return false, nil
	}

	err = errors.New("Interface has different network and db security groups, and assignments")
	tracehelpers.SetStatus(err, span)
	logger.G(ctx).WithError(err).Error("Interface has different network and db security groups")
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

	// Does it exist in the database now?
	var err error
	var fastTx *sql.Tx
	var row *sql.Row
	var count int
retry:
	if fastTx != nil {
		_ = fastTx.Rollback()
	}
	fastTx, err = vpcService.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelSerializable})
	if err != nil {
		err = errors.Wrap(err, "Unable to start serializable transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = fastTx.Rollback()
	}()

	row = fastTx.QueryRowContext(ctx, "SELECT count(*) FROM branch_enis WHERE branch_eni = $1", aws.StringValue(networkInterface.NetworkInterfaceId))
	err = row.Scan(&count)
	if vpcerrors.IsSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot query count of branch ENIs")
		tracehelpers.SetStatus(err, span)
		return err
	}
	err = fastTx.Commit()
	if vpcerrors.IsSerializationFailure(err) {
		goto retry
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot not commit read-only transaction to reconcile missing ENI in database")
		tracehelpers.SetStatus(err, span)
		return err
	}
	if count == 1 {
		return nil
	}

	if aws.StringValue(networkInterface.Status) == inUse {
		err = fmt.Errorf("Wanted to delete interface %q from EC2, but describe call says it is in use", aws.StringValue(networkInterface.NetworkInterfaceId))
		logger.G(ctx).WithError(err).Warning()
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).Warning("Deleting ENI from AWS, as we didn't create it (as far as we can tell)")
	_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: networkInterface.NetworkInterfaceId,
	})
	if err == nil {
		return nil
	}
	awsErr := ec2wrapper.RetrieveEC2Error(err)
	if awsErr != nil {
		if awsErr.Code() == ec2wrapper.InvalidNetworkInterfaceIDNotFound {
			return nil
		}
		return ec2wrapper.HandleEC2Error(err, span)
	}

	err = errors.Wrap(err, "Received 'generic' (non-AWS) error")
	tracehelpers.SetStatus(err, span)
	return err
}

func (vpcService *vpcService) reconcileBranchENIsLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "reconcile_branch_enis",
		itemLister: vpcService.getBranchENIRegionAccounts,
		workFunc:   vpcService.reconcileBranchENILoop,
	}
}
