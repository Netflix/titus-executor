package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/hashicorp/go-multierror"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
)

// Errors that indicate a network interface is in use:
// - InvalidParameterValue

// 1. Mark as deleting in the db by setting deleted_at
// 2. If it existed in the database [we may want to change this behaviour], delete it from AWS
// 3. If we received an error and it's an AWS error, and it's not InvalidNetworkInterfaceID.NotFound,
//    then untombstone the interface, if we tombstoned it [non-AWS error, do not untombstone] because we assume it means
//    the interface still exists
func (vpcService *vpcService) deleteTrunkInterface(ctx context.Context, session *ec2wrapper.EC2Session, networkInterfaceID string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "deleteTrunkInterface")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", networkInterfaceID))

	existed, previousTombstone, err := vpcService.tombstoneTrunkNetworkInterface(ctx, networkInterfaceID)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}
	span.AddAttributes(trace.BoolAttribute("existed", existed))
	if previousTombstone != nil {
		span.AddAttributes(trace.StringAttribute("tombstone", previousTombstone.String()))
	}

	logger.G(ctx).WithField("previousTombstone", previousTombstone).Info("Trying to delete interface that was previously tombstoned")
	if existed {
		_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{
			NetworkInterfaceId: aws.String(networkInterfaceID),
		})
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok {
				if awsErr.Code() != "InvalidNetworkInterfaceID.NotFound" {
					// untombstone the interface.
					// TODO: Do not untombstone the interface for all errors
					err2 := vpcService.untombstoneTrunkNetworkInterface(ctx, networkInterfaceID)
					if err2 != nil {
						result := multierror.Append(err, err2)
						tracehelpers.SetStatus(result, span)
						return result
					}
					return ec2wrapper.HandleEC2Error(err, span)
				}
			} else {
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	err = vpcService.hardDeleteTrunkInterface(ctx, networkInterfaceID)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) hardDeleteTrunkInterface(ctx context.Context, networkInterfaceID string) error {
	ctx, span := trace.StartSpan(ctx, "hardDeleteTrunkInterface")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	_, err = tx.ExecContext(ctx, "DELETE FROM trunk_enis WHERE trunk_eni = $1", networkInterfaceID)
	if err != nil {
		err = errors.Wrap(err, "Could delete trunk ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM branch_eni_attachments WHERE trunk_eni = $1", networkInterfaceID)
	if err != nil {
		err = errors.Wrap(err, "Could branch ENI attachments for trunk ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction, after hard deleting trunk interface")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) untombstoneTrunkNetworkInterface(ctx context.Context, networkInterfaceID string) error {
	ctx, span := trace.StartSpan(ctx, "tombstoneTrunkNetworkInterface")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	_, err = tx.ExecContext(ctx, "UPDATE trunk_enis SET deleted_at = NULL WHERE trunk_eni = $1", networkInterfaceID)
	if err != nil {
		err = errors.Wrap(err, "Could unset tombstone on ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction, after untombstoning ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) getTrunkNetworkInterfaceTombstone(ctx context.Context, networkInterfaceID string) (bool, *time.Time, error) {
	ctx, span := trace.StartSpan(ctx, "getTrunkNetworkInterfaceTombstone")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return false, nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	row := tx.QueryRowContext(ctx, "SELECT deleted_at FROM trunk_enis WHERE trunk_eni = $1", networkInterfaceID)
	var deletedAt pq.NullTime
	err = row.Scan(&deletedAt)
	if err == sql.ErrNoRows {
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction, after found non-existent trunk ENI")
			tracehelpers.SetStatus(err, span)
			return false, nil, err
		}
		return false, nil, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot read deleted_at from database for trunk_eni")
		tracehelpers.SetStatus(err, span)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		tracehelpers.SetStatus(err, span)
		return true, nil, err
	}

	if deletedAt.Valid {
		// This has already been tombstoned previously. Dope.
		return true, &deletedAt.Time, nil
	}

	return true, nil, nil
}

func (vpcService *vpcService) tombstoneTrunkNetworkInterface(ctx context.Context, networkInterfaceID string) (bool, *time.Time, error) {
	ctx, span := trace.StartSpan(ctx, "tombstoneTrunkNetworkInterface")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return false, nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	row := tx.QueryRowContext(ctx, "SELECT deleted_at FROM trunk_enis WHERE trunk_eni = $1", networkInterfaceID)
	var deletedAt pq.NullTime
	err = row.Scan(&deletedAt)
	if err == sql.ErrNoRows {
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction, after found non-existent trunk ENI")
			tracehelpers.SetStatus(err, span)
			return false, nil, err
		}
		return false, nil, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot read deleted_at from database for trunk_eni")
		tracehelpers.SetStatus(err, span)
	}

	if deletedAt.Valid {
		// This has already been tombstoned previously. Dope.
		err = tx.Commit()
		if err != nil {
			err = errors.Wrap(err, "Cannot commit transaction, after already tombstoned ENI")
			tracehelpers.SetStatus(err, span)
			return true, nil, err
		}
		return true, &deletedAt.Time, nil
	}

	_, err = tx.ExecContext(ctx, "UPDATE trunk_enis SET deleted_at = now() WHERE trunk_eni = $1", networkInterfaceID)
	if err != nil {
		err = errors.Wrap(err, "Could not update tombstone on ENI")
		tracehelpers.SetStatus(err, span)
		return true, nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction, after tombstoning ENI")
		tracehelpers.SetStatus(err, span)
		return true, nil, err
	}

	return true, nil, nil
}

func (vpcService *vpcService) createNewTrunkENI(ctx context.Context, session *ec2wrapper.EC2Session, subnetID *string) (*ec2.NetworkInterface, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "createNewTrunkENI")
	defer span.End()

	createNetworkInterfaceInput := ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(vpc.TrunkNetworkInterfaceDescription),
		InterfaceType:    aws.String("trunk"),
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         subnetID,
	}

	// TODO: Record creation of the interface
	createNetworkInterfaceResult, err := session.CreateNetworkInterface(ctx, createNetworkInterfaceInput)
	if err != nil {
		err = errors.Wrap(err, "Cannot create network interface")
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	modifyNetworkInterfaceAttributeInput := ec2.ModifyNetworkInterfaceAttributeInput{
		SourceDestCheck:    &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}
	_, err = session.ModifyNetworkInterfaceAttribute(ctx, modifyNetworkInterfaceAttributeInput)
	// This isn't actually the end of the world as long as someone comes and fixes it later
	if err != nil {
		err = errors.Wrap(err, "Could not configure network interface to disable source / dest check")
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	err = insertTrunkENIIntoDB(ctx, tx, createNetworkInterfaceResult.NetworkInterface)
	if err != nil {
		err = errors.Wrap(err, "Cannot update trunk enis")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return createNetworkInterfaceResult.NetworkInterface, nil
}

// inserts an ENI into the database in a non-conflicting way, and tombstones it
func insertTrunkENIIntoDB(ctx context.Context, tx *sql.Tx, eni *ec2.NetworkInterface) error {
	// TODO: Use the availability_zones table
	region := azToRegionRegexp.FindString(aws.StringValue(eni.AvailabilityZone))

	_, err := tx.ExecContext(ctx, `
INSERT INTO trunk_enis(trunk_eni, account_id, az, subnet_id, vpc_id, region)
VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (trunk_eni) DO
UPDATE 
SET deleted_at = NULL
`,
		aws.StringValue(eni.NetworkInterfaceId),
		aws.StringValue(eni.OwnerId),
		aws.StringValue(eni.AvailabilityZone),
		aws.StringValue(eni.SubnetId),
		aws.StringValue(eni.VpcId),
		region,
	)
	return err
}

func (vpcService *vpcService) getTrunkENIRegionAccounts(ctx context.Context) ([]keyedItem, error) {
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
	rows, err := tx.QueryContext(ctx, "SELECT region, account_id FROM trunk_enis GROUP BY region, account_id")
	if err != nil {
		return nil, err
	}

	ret := []keyedItem{}
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
