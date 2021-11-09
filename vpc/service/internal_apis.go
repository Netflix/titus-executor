package service

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Netflix/titus-executor/logger"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/lib/pq"
	"github.com/pkg/errors"

	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These are internal
func (vpcService *vpcService) AssociateTrunkNetworkInterface(ctx context.Context, req *vpcapi.AssociateTrunkNetworkInterfaceRequest) (*vpcapi.AssociateTrunkNetworkInterfaceResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssociateTrunkNetworkInterface")
	defer span.End()

	if req.BranchENI == "" {
		return nil, status.Error(codes.InvalidArgument, "Branch ENI must be specified")
	}

	switch id := (req.TrunkNetworkInterfaceIdentifier).(type) {
	case *vpcapi.AssociateTrunkNetworkInterfaceRequest_InstanceIdentity:
		if id.InstanceIdentity == nil {
			return nil, status.Error(codes.InvalidArgument, "instance id must be specified")
		}
		_, _, trunkENI, err := vpcService.getSessionAndTrunkInterface(ctx, id.InstanceIdentity)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		return vpcService.doAssociateTrunkNetworkInterface(ctx, aws.StringValue(trunkENI.NetworkInterfaceId), req.BranchENI, int(req.VlanId))
	case *vpcapi.AssociateTrunkNetworkInterfaceRequest_TrunkENI:
		return vpcService.doAssociateTrunkNetworkInterface(ctx, id.TrunkENI, req.BranchENI, int(req.VlanId))
	}

	return nil, status.Error(codes.InvalidArgument, "Could not determine trunk ENI")
}

func (vpcService *vpcService) doAssociateTrunkNetworkInterface(ctx context.Context, trunk, branch string, vlanID int) (*vpcapi.AssociateTrunkNetworkInterfaceResponse, error) {
	ctx, span := trace.StartSpan(ctx, "doAssociateTrunkNetworkInterface")
	defer span.End()

	if vlanID == 0 {
		return nil, status.Error(codes.Unimplemented, "Automatic vlan selection is currently not implemented (one must be specified)")
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `SELECT (SELECT region
	FROM availability_zones
	WHERE zone_name = branch_enis.az
	AND account_id = branch_enis.account_id), account_id, az FROM branch_enis
	WHERE branch_eni = $1
	FOR NO KEY UPDATE`, branch)

	var branchENIRegion, branchENIAccountID, branchENIAZ string
	err = row.Scan(&branchENIRegion, &branchENIAccountID, &branchENIAZ)
	if err == sql.ErrNoRows {
		err = status.Errorf(codes.NotFound, "branch ENI %s not found in database", branch)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Could not query branch ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	var trunkENIRegion, trunkENIAccountID string
	row = tx.QueryRowContext(ctx, "SELECT region, account_id FROM trunk_enis WHERE trunk_eni = $1", trunk)
	err = row.Scan(&trunkENIRegion, &trunkENIAccountID)
	if err == sql.ErrNoRows {
		err = status.Errorf(codes.NotFound, "trunk ENI %s not found in database", trunk)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Could not query trunk ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	branchENISession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: branchENIRegion, AccountID: branchENIAccountID})
	if err != nil {
		err = errors.Wrap(err, "Could not get EC2 session for branch ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	trunkENISession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: trunkENIRegion, AccountID: trunkENIAccountID})
	if err != nil {
		err = errors.Wrap(err, "Could not get EC2 session for trunk ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = vpcService.ensureBranchENIPermissionV3(ctx, tx, trunkENIAccountID, branchENISession, &branchENI{
		id:        branch,
		az:        branchENIAZ,
		accountID: branchENIAccountID,
	})
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	associationID, err := vpcService.associateNetworkInterface(ctx, tx, trunkENISession,
		association{
			trunkENI:  trunk,
			branchENI: branch,
		},
		vlanID)
	if err != nil {
		if vpcerrors.IsPersistentError(err) {
			logger.G(ctx).WithError(err).Error("Received persistent error, committing current state, and returning error")
			err2 := tx.Commit()
			if err2 != nil {
				logger.G(ctx).WithError(err2).Error("Failed to commit transaction early due to persistent AWS error")
			}
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &vpcapi.AssociateTrunkNetworkInterfaceResponse{AssociationId: *associationID}, nil

}

func (vpcService *vpcService) DisassociateTrunkNetworkInterface(ctx context.Context, req *vpcapi.DisassociateTrunkNetworkInterfaceRequest) (*vpcapi.DisassociateTrunkNetworkInterfaceResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssociateTrunkNetworkInterface")
	defer span.End()

	switch id := (req.Key).(type) {
	case *vpcapi.DisassociateTrunkNetworkInterfaceRequest_AssociationId:
		return vpcService.doDisassociateTrunkNetworkInterface(ctx, id.AssociationId, req.Force)
	}

	return nil, status.Error(codes.InvalidArgument, "Could not determine associationID")

}

func (vpcService *vpcService) doDisassociateTrunkNetworkInterface(ctx context.Context, associationID string, force bool) (*vpcapi.DisassociateTrunkNetworkInterfaceResponse, error) {
	ctx, span := trace.StartSpan(ctx, "doDisassociateTrunkNetworkInterface")
	defer span.End()

	if associationID == "" {
		return nil, status.Error(codes.InvalidArgument, "associationID must be specified")
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	err = vpcService.disassociateNetworkInterface(ctx, tx, nil, associationID, force)
	if err != nil {
		if vpcerrors.IsPersistentError(err) {
			logger.G(ctx).WithError(err).Error("Received persistent error, committing current state, and returning error")
			err2 := tx.Commit()
			if err2 != nil {
				logger.G(ctx).WithError(err2).Error("Failed to commit transaction early")
			}
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &vpcapi.DisassociateTrunkNetworkInterfaceResponse{}, nil
}

func (vpcService *vpcService) DescribeTrunkNetworkInterface(ctx context.Context, req *vpcapi.DescribeTrunkNetworkInterfaceRequest) (*vpcapi.DescribeTrunkNetworkInterfaceResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "DescribeTrunkNetworkInterface")
	defer span.End()

	switch req := (req.TrunkNetworkInterfaceIdentifier).(type) {
	case *vpcapi.DescribeTrunkNetworkInterfaceRequest_InstanceIdentity:
		if req.InstanceIdentity == nil {
			return nil, status.Error(codes.InvalidArgument, "instance id must be specified")
		}
		_, _, trunkENI, err := vpcService.getSessionAndTrunkInterface(ctx, req.InstanceIdentity)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		return vpcService.doDescribeTrunkNetworkInterface(ctx, aws.StringValue(trunkENI.NetworkInterfaceId))
	case *vpcapi.DescribeTrunkNetworkInterfaceRequest_TrunkENI:
		return vpcService.doDescribeTrunkNetworkInterface(ctx, req.TrunkENI)
	}

	return nil, status.Error(codes.InvalidArgument, "Could not determine trunk ENI")
}

func (vpcService *vpcService) doDescribeTrunkNetworkInterface(ctx context.Context, eni string) (*vpcapi.DescribeTrunkNetworkInterfaceResponse, error) {
	ctx, span := trace.StartSpan(ctx, "doDescribeTrunkNetworkInterface")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("eni", eni))

	trunkENI := vpcapi.DescribeTrunkNetworkInterfaceResponse_TrunkENI{
		Id: eni,
	}
	associations := []*vpcapi.DescribeTrunkNetworkInterfaceResponse_TrunkNetworkInterfaceAssociation{}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "SELECT account_id, created_at, az, subnet_id, vpc_id, region FROM trunk_enis WHERE trunk_eni = $1", eni)
	var createdAt time.Time
	err = row.Scan(
		&trunkENI.AccountId,
		&createdAt,
		&trunkENI.Az,
		&trunkENI.SubnetId,
		&trunkENI.VpcId,
		&trunkENI.Region,
	)
	if err == sql.ErrNoRows {
		err = status.Errorf(codes.NotFound, "trunk ENI %s not found in database", eni)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Could not query database for trunk ENI")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	trunkENI.CreatedAt = timestamppb.New(createdAt)

	rows, err := tx.QueryContext(ctx, `
SELECT branch_enis.branch_eni,
       association_id,
       idx,
       branch_enis.account_id,
       branch_enis.created_at,
       branch_enis.subnet_id,
       branch_enis.vpc_id,
       COALESCE(branch_enis.last_assigned_to, TIMESTAMP 'EPOCH'),
       branch_enis.modified_at,
       branch_enis.security_groups
FROM branch_eni_attachments
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE trunk_eni = $1
`, eni)
	if err != nil {
		err = errors.Wrap(err, "Could not query database for branch ENIs")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	for rows.Next() {
		association := vpcapi.DescribeTrunkNetworkInterfaceResponse_TrunkNetworkInterfaceAssociation{}
		branchENI := vpcapi.DescribeTrunkNetworkInterfaceResponse_BranchENI{}
		var createdAt, lastAssignedTo, modifiedAt time.Time
		securityGroups := []string{}
		err = rows.Scan(
			&branchENI.Id,
			&association.AssociationId,
			&association.VlanId,
			&branchENI.AccountId,
			&createdAt,
			&branchENI.SubnetId,
			&branchENI.VpcId,
			&lastAssignedTo,
			&modifiedAt,
			pq.Array(&securityGroups),
		)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan database row for branch ENI")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		branchENI.SecurityGroupIds = securityGroups
		branchENI.CreatedAt = timestamppb.New(createdAt)
		branchENI.ModifiedAt = timestamppb.New(modifiedAt)
		branchENI.LastAssignedTo = timestamppb.New(lastAssignedTo)
		association.BranchENI = &branchENI
		associations = append(associations, &association)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &vpcapi.DescribeTrunkNetworkInterfaceResponse{
		TrunkENI:     &trunkENI,
		Associations: associations,
	}, nil
}

func (vpcService *vpcService) DetachBranchNetworkInterface(ctx context.Context, req *vpcapi.DetachBranchNetworkInterfaceRequest) (*vpcapi.DetachBranchNetworkInterfaceResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "DetachBranchNetworkInterface")
	defer span.End()

	switch id := (req.TrunkNetworkInterfaceIdentifier).(type) {
	case *vpcapi.DetachBranchNetworkInterfaceRequest_InstanceIdentity:
		if id.InstanceIdentity == nil {
			return nil, status.Error(codes.InvalidArgument, "instance id must be specified")
		}
		session, _, trunkENI, err := vpcService.getSessionAndTrunkInterface(ctx, id.InstanceIdentity)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		return vpcService.doDetachBranchNetworkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId))
	}

	return nil, status.Error(codes.InvalidArgument, "Could not determine trunk ENI")
}

func (vpcService *vpcService) doDetachBranchNetworkInterface(ctx context.Context, session *ec2wrapper.EC2Session, trunkENI string) (*vpcapi.DetachBranchNetworkInterfaceResponse, error) {
	ctx, span := trace.StartSpan(ctx, "doDetachBranchNetworkInterface")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot start database transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	attachmentIdx, branchENI, associationID, err := vpcService.detachBranchENI(ctx, tx, session, trunkENI)
	if err != nil {
		if vpcerrors.IsPersistentError(err) {
			logger.G(ctx).WithError(err).Error("Received persistent error, committing current state, and returning error")
			err2 := tx.Commit()
			if err2 != nil {
				logger.G(ctx).WithError(err2).Error("Failed to commit transaction early")
			}
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &vpcapi.DetachBranchNetworkInterfaceResponse{
		VlanId:        uint64(attachmentIdx),
		BranchENI:     branchENI,
		AssociationID: associationID,
	}, nil
}

func (vpcService *vpcService) ResetSecurityGroup(ctx context.Context, request *titus.ResetSecurityGroupRequest) (*titus.ResetSecurityGroupResponse, error) {
	var resetSgTx *sql.Tx
	var err error
	var count int
	var defaultSecurityGroupID, region, account string

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "ResetSecurityGroup")
	defer span.End()

	resetSgTx, err = vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = errors.Wrap(err, "Unable to begin serializable transaction")
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}

	sgToDelete := request.GetSecurityGroupID()

	// First get the default security group that we will replace the Reset SG with
	logger.G(ctx).WithField("resetSg", sgToDelete).Debug("Get Default security group ID of the VPC to use in place of the SG")
	row := resetSgTx.QueryRowContext(ctx, `
SELECT region, account, group_id FROM security_groups WHERE  group_name='default' and account = (SELECT account FROM security_groups WHERE group_id = $1 limit 1)
		`, sgToDelete)
	err = row.Scan(&region, &account, &defaultSecurityGroupID)
	if err != nil {
		err = fmt.Errorf("Could not get region, account and def SG of %s: %w ", sgToDelete, err)
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}

	// Create the ec2 session to call AWS with the changed SG and before beginning the next Tx
	resetSgSession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: region, AccountID: account})
	if err != nil {
		err = fmt.Errorf("Unable to create an ec2 session to reset SG %s : %w ", sgToDelete, err)
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}

	//Start new transaction
	resetSgTx, err = beginSerializableTx(ctx, vpcService.db)
	if err != nil {
		err = errors.Wrap(err, "Unable to begin serializable transaction")
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}

	logger.G(ctx).WithField("resetSg", sgToDelete).Debug("Check if the SG to be reset is associated with a container")
	// Check if the SG to be reset is associated with a container
	rows, err := resetSgTx.QueryContext(ctx, `
SELECT COUNT(*) FROM branch_enis
WHERE ARRAY[$1] <@ security_groups AND branch_eni IN
(SELECT branch_eni FROM branch_eni_attachments WHERE branch_eni_attachments.association_id IN
	(SELECT branch_eni_association FROM assignments))
		`, sgToDelete)
	if err != nil {
		err = fmt.Errorf("Could not query database for branch ENIs containing the SG %s: %w ", sgToDelete, err)
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			err = fmt.Errorf("Could not get count of associations from query results %s: %w ", sgToDelete, err)
			tracehelpers.SetStatus(err, span)
			return &titus.ResetSecurityGroupResponse{}, status.Errorf(codes.InvalidArgument,
				"Could not get count of associations from query results")
		}
	}

	if count != 0 {
		//We cannot process the delete SG request as there are containers actively using the ENI that uses this SG
		return &titus.ResetSecurityGroupResponse{}, status.Errorf(codes.FailedPrecondition,
			"%s is attached to an ENI with active association", sgToDelete)
	}

	// Reset the SG Id to the default SG
	logger.G(ctx).WithField("resetSg", sgToDelete).Debug("Reset the SG Id to default")
	rows, err = resetSgTx.QueryContext(ctx,
		"UPDATE branch_enis SET security_groups = ARRAY[$1],dirty_security_groups=true WHERE ARRAY[$2] <@ security_groups returning branch_eni",
		defaultSecurityGroupID, sgToDelete)
	if err != nil {
		err = fmt.Errorf("Cannot mark security groups as dirty for %s : %w", sgToDelete, err)
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}
	defer rows.Close()

	var enisWithSgToUpdate []string
	for rows.Next() {
		var updatedEni string
		err := rows.Scan(&updatedEni)
		if err != nil {
			err = fmt.Errorf("Could not get ENI that was updated to reset %s: %w ", sgToDelete, err)
			tracehelpers.SetStatus(err, span)
			return &titus.ResetSecurityGroupResponse{}, err
		}
		enisWithSgToUpdate = append(enisWithSgToUpdate, updatedEni)
		logger.G(ctx).WithField("resetSg", sgToDelete).Debug("Need to update ", updatedEni, " to default SG ", defaultSecurityGroupID)
	}

	err = resetSgTx.Commit()
	if err != nil {
		err = fmt.Errorf("Unable to commit transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return &titus.ResetSecurityGroupResponse{}, err
	}

	//Call AWS to change the interface SG ID to the default SG ID of the VPC
	logger.G(ctx).WithField("resetSg", sgToDelete).Debug("Call AWS to change the interface SG ID to the default SG ID of the VPC")

	defaultSgIDS := make([]string, 0)
	defaultSgIDS = append(defaultSgIDS, defaultSecurityGroupID)

	//lock eni no key update and then call the AWS API (still dirty and sg is default), and reset the dirty flag to false
	for _, branchEni := range enisWithSgToUpdate {
		err := vpcService.updateENISecurityGroups(ctx, resetSgSession, defaultSgIDS, branchEni, sgToDelete)
		if err != nil {
			err = fmt.Errorf("Unable to modify SG ID on AWS to default for %s: %w", branchEni, err)
			tracehelpers.SetStatus(err, span)
			return &titus.ResetSecurityGroupResponse{}, err
		}
	}
	logger.G(ctx).WithField("resetSg", sgToDelete).Debug("Reset SG succeeded.")
	return &titus.ResetSecurityGroupResponse{}, nil
}

//Update the SG on AWS with the default SG after verifying that the `dirty_security_groups` is unchanged
func (vpcService *vpcService) updateENISecurityGroups(ctx context.Context, session *ec2wrapper.EC2Session, defSgS []string, eni string, sgToDelete string) error {
	ctx, span := trace.StartSpan(ctx, "updateENISecurityGroups")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot begin Tx")
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT security_groups, dirty_security_groups FROM branch_enis WHERE branch_enis.branch_eni = $1
FOR NO KEY UPDATE OF branch_enis`, eni)

	var securityGroups []string
	var dirtySecurityGroups bool
	err = row.Scan(pq.Array(&securityGroups), &dirtySecurityGroups)
	if err != nil {
		err = errors.Wrap(err, "Unable to scan branch_enis for dirty_security_groups")
		tracehelpers.SetStatus(err, span)
		return err
	}

	//Check if anything changed on the SG <-> ENI association
	if !dirtySecurityGroups {
		logger.G(ctx).WithField("resetSg", sgToDelete).Debug("dirtySecurityGroups for ", eni, " was set to false")
		return nil
	}

	if len(securityGroups) != 1 && securityGroups[0] == defSgS[0] {
		logger.G(ctx).WithField("resetSg", sgToDelete).Debug("security groups for ", eni, " was non-default")
		return nil
	}

	_, err = session.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(eni),
		Groups:             aws.StringSlice(defSgS),
	})
	if err != nil {
		return ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET dirty_security_groups = false, modified_at = transaction_timestamp(), aws_security_groups_updated = transaction_timestamp() WHERE branch_eni = $1", eni)
	if err != nil {
		err = errors.Wrap(err, "Unable to update database to set security groups to non-dirty")
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrapf(err, "Unable to commit transaction")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}
