package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"

	"github.com/Netflix/titus-executor/logger"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/golang/protobuf/ptypes" //nolint: staticcheck
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
	trunkENI.CreatedAt, _ = ptypes.TimestampProto(createdAt) //nolint: staticcheck

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
		branchENI.CreatedAt, _ = ptypes.TimestampProto(createdAt)           //nolint: staticcheck
		branchENI.ModifiedAt, _ = ptypes.TimestampProto(modifiedAt)         //nolint: staticcheck
		branchENI.LastAssignedTo, _ = ptypes.TimestampProto(lastAssignedTo) //nolint: staticcheck
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
