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
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	timeBetweenSecurityGroupReconcilation = 5 * time.Minute
	securityGroupReconcilationTimeout     = 10 * time.Minute
)

func (vpcService *vpcService) reconcileSecurityGroupsForRegionAccountLoop(ctx context.Context, protoItem data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*regionAccount)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"region":    item.region,
		"accountID": item.accountID,
	})
	for {
		err := vpcService.reconcileSecurityGroupsForRegionAccount(ctx, item)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Failed to reconcile security groups")
		}
		err = waitFor(ctx, timeBetweenSecurityGroupReconcilation)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) reconcileSecurityGroupsForRegionAccount(ctx context.Context, protoAccount data.KeyedItem) error {
	ctx, cancel := context.WithTimeout(ctx, securityGroupReconcilationTimeout)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "reconcileSecurityGroupsForRegionAccount")
	defer span.End()

	account := protoAccount.(*regionAccount)
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

	logger.G(ctx).WithFields(map[string]interface{}{
		"region":    account.region,
		"accountID": account.accountID,
	}).Info("Beginning reconcilation of security groups")

	securityGroups := []*ec2.SecurityGroup{}
	describeSecurityGroupsInput := ec2.DescribeSecurityGroupsInput{
		MaxResults: aws.Int64(250),
	}
	for {
		output, err := session.DescribeSecurityGroups(ctx, describeSecurityGroupsInput)
		if err != nil {
			logger.G(ctx).WithError(err).Error()
			return ec2wrapper.HandleEC2Error(err, span)
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)

		if output.NextToken == nil {
			break
		}
		describeSecurityGroupsInput.NextToken = output.NextToken
	}

	// Reconcilation
	// 1. Grab the security group (ids) from the database
	// 2. upsert new SGs
	// 3. delete the non-exist SG IDs
	inDatabaseSecurityGroupIDs := sets.NewString()
	inAWSSecurityGroupIDs := sets.NewString()
	for idx := range securityGroups {
		inAWSSecurityGroupIDs.Insert(aws.StringValue(securityGroups[idx].GroupId))
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = fmt.Errorf("Could not start database transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, "SELECT group_id FROM security_groups WHERE region = $1 AND account = $2", account.region, account.accountID)
	if err != nil {
		err = fmt.Errorf("Could query for databases: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	for rows.Next() {
		var securityGroupID string
		err = rows.Scan(&securityGroupID)
		if err != nil {
			err = fmt.Errorf("Unable to scan security group ID: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
		inDatabaseSecurityGroupIDs.Insert(securityGroupID)
	}

	securityGroupToDelete := inDatabaseSecurityGroupIDs.Difference(inAWSSecurityGroupIDs)
	for _, sg := range securityGroups {
		err = insertSecurityGroup(ctx, tx, sg, account)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	if securityGroupToDelete.Len() > 0 {
		_, err = tx.ExecContext(ctx, "DELETE FROM security_groups WHERE group_id = any($1)", pq.Array(securityGroupToDelete.UnsortedList()))
		if err != nil {
			if err != nil {
				err = fmt.Errorf("Unable to delete non-existent security groups: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		err = fmt.Errorf("Unable to commit transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func insertSecurityGroup(ctx context.Context, tx *sql.Tx, sg *ec2.SecurityGroup, account *regionAccount) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO security_groups(group_id, group_name, owner_id, vpc_id, region, account) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (group_id) DO UPDATE SET group_name = $2",
		aws.StringValue(sg.GroupId), aws.StringValue(sg.GroupName), aws.StringValue(sg.OwnerId), aws.StringValue(sg.VpcId), account.region, account.accountID)
	if err != nil {
		return fmt.Errorf("Unable to update security group %s: %w", aws.StringValue(sg.GroupId), err)
	}

	return nil
}

func (vpcService *vpcService) reconcileSecurityGroupsLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "reconcile_security_groups",
		itemLister: vpcService.getRegionAccounts,
		workFunc:   vpcService.reconcileSecurityGroupsForRegionAccountLoop,
	}
}
