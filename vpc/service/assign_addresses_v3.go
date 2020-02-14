package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	invalidParameterValue = "InvalidParameterValue"
)

var (
	errAllENIsInUse                = errors.New("All ENIs in use, cannot deallocate any ENIs")
	errAssignmentMethodNotPossible = errors.New("Assignment method is not possible")
)

func (vpcService *vpcService) getSessionAndTrunkInterface(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity) (*ec2wrapper.EC2Session, *ec2.Instance, *ec2.InstanceNetworkInterface, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "getSessionAndTrunkInterface")
	defer span.End()

	instanceSession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: instanceIdentity.Region, AccountID: instanceIdentity.AccountID})
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, nil, nil, err
	}
	instance, _, err := instanceSession.GetInstance(ctx, instanceIdentity.InstanceID, false)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, nil, nil, err
	}

	trunkENI := vpcService.getTrunkENI(instance)
	if trunkENI == nil {
		instance, _, err = instanceSession.GetInstance(ctx, instanceIdentity.InstanceID, true)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, nil, nil, err
		}
		trunkENI = vpcService.getTrunkENI(instance)
	}
	if trunkENI == nil {
		err = status.Error(codes.FailedPrecondition, "Instance does not have trunk ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, nil, nil, err
	}
	return instanceSession, instance, trunkENI, nil
}

type subnet struct {
	az        string
	vpcID     string
	accountID string
	subnetID  string
	cidr      string
}

type branchENI struct {
	id            string
	az            string
	associationID string
	accountID     string
	idx           int
}

func (vpcService *vpcService) getSubnet(ctx context.Context, az, accountID string, subnetIDs []string) (*subnet, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "getSubnet")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var row *sql.Row
	if len(subnetIDs) == 0 {
		row = tx.QueryRowContext(ctx, "SELECT subnets.az, subnets.vpc_id, subnets.account_id, subnets.subnet_id, subnets.cidr FROM subnets JOIN account_mapping ON subnets.subnet_id = account_mapping.subnet_id WHERE account_id = $1 AND subnets.az  = $2", accountID, az)
	} else {
		row = tx.QueryRowContext(ctx, "SELECT az, vpc_id, account_id, subnet_id, cidr FROM subnets WHERE az = $1 AND subnet_id = any($2) LIMIT 1", az, pq.Array(subnetIDs))
	}
	ret := subnet{}
	err = row.Scan(&ret.az, &ret.vpcID, &ret.accountID, &ret.subnetID, &ret.cidr)
	if err == sql.ErrNoRows {
		if len(subnetIDs) == 0 {
			err = fmt.Errorf("No subnet found matching IDs %s in az %s", subnetIDs, az)
		} else {
			err = fmt.Errorf("No subnet found in account %s in az %s", accountID, az)
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch subnet ID from database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	return &ret, nil
}

type staticAllocation struct {
	az       string
	region   string
	subnetID string
}

func (vpcService *vpcService) getStaticAllocation(ctx context.Context, alloc *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation) (*staticAllocation, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "getStaticAllocation")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "SELECT az, region, subnet_id FROM ip_addresses WHERE id = $1", alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid)
	var retAlloc staticAllocation
	err = row.Scan(&retAlloc.az, &retAlloc.region, &retAlloc.subnetID)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Cannot read static allocation").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &retAlloc, nil
}

func (vpcService *vpcService) AssignIPV3(ctx context.Context, req *vpcapi.AssignIPRequestV3) (*vpcapi.AssignIPResponseV3, error) {
	// 1. Get the trunk ENI
	// 2. Choose the subnet we're "scheduling" into
	// 3. Check if there are any branch ENIs already attached to the trunk ENI with the subnet + security groups wanted, and have fewer than 50 assignments (for share)
	// 4. Check if there are any branch ENIs with the subnet with 0 allocations (FOR UPDATE), set the security groups, and then lock the ENI, and so on.
	// 5. Attach an ENI that fulfills the requirements
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssignIPv3")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"instance": req.InstanceIdentity.InstanceID,
	})
	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID))

	if req.TaskId == "" {
		err := status.Error(codes.InvalidArgument, "Task ID is not specified")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ctx = logger.WithFields(ctx, map[string]interface{}{
		"taskID": req.TaskId,
	})
	span.AddAttributes(
		trace.StringAttribute("taskID", req.TaskId))

	instanceSession, instance, trunkENI, err := vpcService.getSessionAndTrunkInterface(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	if static, ok := req.Ipv4.(*vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation); ok {
		logger.G(ctx).WithField("static", static).Debug("Received static address allocation, retrieving subnet from allocation")
		alloc, err := vpcService.getStaticAllocation(ctx, static)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		if len(req.Subnets) > 0 {
			if !sets.NewString(req.Subnets...).Has(alloc.subnetID) {
				err = fmt.Errorf("Allocation in subnet %s, but request asked for in subnet ids %q", alloc.subnetID, req.Subnets)
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		}
		req.Subnets = []string{alloc.subnetID}
	}

	accountID := aws.StringValue(trunkENI.OwnerId)
	if req.AccountID != "" {
		accountID = req.AccountID
	}

	subnet, err := vpcService.getSubnet(ctx, aws.StringValue(instance.Placement.AvailabilityZone), accountID, req.Subnets)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	span.AddAttributes(trace.StringAttribute("subnet", subnet.subnetID))
	logger.G(ctx).WithField("subnet", subnet).Debug("Chose subnet to schedule into")

	maxIPAddresses, err := vpc.GetMaxIPAddresses(aws.StringValue(instance.InstanceType))
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	resp, err := vpcService.assignIPWithSharedENI(ctx, req, subnet, trunkENI, instance, maxIPAddresses)
	if err == nil {
		return resp, err
	}

	if err != errAssignmentMethodNotPossible {
		return nil, err
	}

	resp, err = vpcService.assignIPWithChangeSGOnENI(ctx, req, subnet, trunkENI, instance, maxIPAddresses)
	if err == nil {
		return resp, err
	}
	if err != errAssignmentMethodNotPossible {
		return nil, err
	}

	resp, err = vpcService.assignIPWithAddENI(ctx, req, instanceSession, subnet, trunkENI, instance, maxIPAddresses)
	if err == nil {
		return resp, err
	}

	return nil, status.Errorf(codes.Unknown, "Could not complete request: %s", err.Error())
}

func (vpcService *vpcService) getUnattachedBranchENIWithSecurityGroups(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, subnetID string, wantedSecurityGroupsIDs []string) (*branchENI, error) {
	ctx, span := trace.StartSpan(ctx, "getUnattachedBranchENIWithSecurityGroups")
	defer span.End()

	ec2client := ec2.New(session.Session)

	var eni branchENI
	var hasSecurityGroupIDs []string
	rowContext := tx.QueryRowContext(ctx, `
	SELECT branch_eni, az, account_id, security_groups
	FROM branch_enis
	WHERE branch_eni NOT IN
		(SELECT branch_eni
		 FROM branch_eni_attachments)
	  AND subnet_id = $1
	ORDER BY RANDOM()
	FOR
	UPDATE SKIP LOCKED
	LIMIT 1
	`, subnetID)
	err := rowContext.Scan(&eni.id, &eni.az, &eni.accountID, pq.Array(&hasSecurityGroupIDs))
	if err == nil {
		if sets.NewString(wantedSecurityGroupsIDs...).Equal(sets.NewString(hasSecurityGroupIDs...)) {
			return &eni, nil
		}
		_, err = ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			Groups:             aws.StringSlice(wantedSecurityGroupsIDs),
			NetworkInterfaceId: aws.String(eni.id),
		})
		if err != nil {
			err = errors.Wrap(err, "Cannot modify security groups on interface")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		return &eni, nil
	} else if err != sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	createNetworkInterfaceInput := &ec2.CreateNetworkInterfaceInput{
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         aws.String(subnetID),
		Description:      aws.String(vpc.BranchNetworkInterfaceDescription),
		Groups:           aws.StringSlice(wantedSecurityGroupsIDs),
	}

	logger.G(ctx).WithField("createNetworkInterfaceInput", createNetworkInterfaceInput).Debug("Creating Branch ENI")
	createNetworkInterfaceOutput, err := ec2client.CreateNetworkInterface(createNetworkInterfaceInput)
	if err != nil {
		return nil, err
	}

	securityGroupIds := make([]string, len(createNetworkInterfaceOutput.NetworkInterface.Groups))
	for idx := range createNetworkInterfaceOutput.NetworkInterface.Groups {
		securityGroupIds[idx] = aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.Groups[idx].GroupId)
	}
	sort.Strings(securityGroupIds)

	_, err = tx.ExecContext(ctx, "INSERT INTO branch_enis (branch_eni, subnet_id, account_id, az, vpc_id, security_groups, modified_at) VALUES ($1, $2, $3, $4, $5, $6, transaction_timestamp())",
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.SubnetId),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.OwnerId),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.AvailabilityZone),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.VpcId),
		pq.Array(securityGroupIds),
	)
	if err != nil {
		return nil, err
	}

	return &branchENI{
		id:        aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId),
		az:        aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.AvailabilityZone),
		accountID: aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.OwnerId),
	}, nil
}

func (vpcService *vpcService) assignIPWithAddENI(ctx context.Context, req *vpcapi.AssignIPRequestV3, instanceSession *ec2wrapper.EC2Session, s *subnet, trunkENI *ec2.InstanceNetworkInterface, instance *ec2.Instance, maxIPAddresses int) (resp *vpcapi.AssignIPResponseV3, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "assignIPWithAddENI")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		if retErr == nil {
			retErr = tx.Commit()
			if retErr != nil {
				span.SetStatus(traceStatusFromError(err))
			}
		} else {
			_ = tx.Rollback()
		}
	}()

	rows, err := tx.QueryContext(ctx, `SELECT idx FROM branch_eni_attachments WHERE trunk_eni = $1`, aws.StringValue(trunkENI.NetworkInterfaceId))
	if err != nil {
		err = errors.Wrap(err, "Could query database for branch ENI attachments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	usedIndexes := sets.NewInt()
	for rows.Next() {
		var idx int
		err = rows.Scan(&idx)
		if err != nil {
			err = errors.Wrap(err, "Could scan database for attached ENIs on trunk ENI")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		usedIndexes.Insert(idx)
	}

	allIndexes := sets.NewInt()
	maxBranchENIs, err := vpc.GetMaxBranchENIs(aws.StringValue(instance.InstanceType))
	if err != nil {
		err = errors.Wrap(err, "Could get max branch ENIs for instance")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	for i := 1; i <= maxBranchENIs; i++ {
		allIndexes.Insert(i)
	}
	unusedIndexes := allIndexes.Difference(usedIndexes)
	var attachmentIdx int
	if unusedIndexes.Len() == 0 {
		attachmentIdx, err = vpcService.detachBranchENI(ctx, tx, instanceSession, trunkENI)
		if err != nil {
			err = errors.Wrap(err, "Could detach existing branch ENI")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	} else {
		s1 := rand.NewSource(time.Now().UnixNano())
		r1 := rand.New(s1)
		unusedIndexesList := unusedIndexes.UnsortedList()
		attachmentIdx = unusedIndexesList[r1.Intn(len(unusedIndexesList))]
	}

	branchENISession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: azToRegionRegexp.FindString(s.az), AccountID: s.accountID})
	if err != nil {
		err = errors.Wrap(err, "Cannot get session for account / region")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	// This creates a lock on that index. Although there is no way to "fix" the locking problem, this will result in the other txn aborting
	eni, err := vpcService.getUnattachedBranchENIWithSecurityGroups(ctx, tx, branchENISession, s.subnetID, req.SecurityGroupIds)
	if err != nil {
		err = errors.Wrap(err, "Cannot get branch ENI to attach")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	row := tx.QueryRowContext(ctx, "INSERT INTO branch_eni_attachments(branch_eni, trunk_eni, idx, attachment_generation) VALUES ($1, $2, $3, 3) RETURNING id", eni.id, aws.StringValue(trunkENI.NetworkInterfaceId), attachmentIdx)
	var branchENIAttachmentID int
	err = row.Scan(&branchENIAttachmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot create row in branch ENI attachments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	err = vpcService.ensureBranchENIPermissionV3(ctx, tx, trunkENI, branchENISession, eni)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	ec2client := ec2.New(instanceSession.Session)
	association, err := ec2client.AssociateTrunkInterfaceWithContext(ctx, &ec2.AssociateTrunkInterfaceInput{
		BranchInterfaceId: aws.String(eni.id),
		TrunkInterfaceId:  trunkENI.NetworkInterfaceId,
		VlanId:            aws.Int64(int64(attachmentIdx)),
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot associate trunk interface with branch ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_eni_attachments SET association_id = $1 WHERE id = $2", aws.StringValue(association.InterfaceAssociation.AssociationId), branchENIAttachmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot update branch ENI attachments table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	eni.idx = int(aws.Int64Value(association.InterfaceAssociation.VlanId))
	eni.associationID = aws.StringValue(association.InterfaceAssociation.AssociationId)

	return vpcService.assignIPsToENI(ctx, req, tx, branchENISession, s, eni, instance, trunkENI, maxIPAddresses)
}

func (vpcService *vpcService) detachBranchENI(ctx context.Context, tx *sql.Tx, instanceSession *ec2wrapper.EC2Session, trunkENI *ec2.InstanceNetworkInterface) (int, error) {
	ctx, span := trace.StartSpan(ctx, "detachBranchENI")
	defer span.End()

	row := tx.QueryRowContext(ctx, `
DELETE
FROM branch_eni_attachments
WHERE branch_eni =
    (SELECT branch_eni
     FROM branch_eni_attachments
     LEFT JOIN assignments ON branch_eni_attachments.association_id = assignments.branch_eni_association
     WHERE trunk_eni = $1
     GROUP BY branch_eni
     HAVING count(assignment_id) = 0
     ORDER BY COALESCE((SELECT last_used FROM branch_eni_last_used WHERE branch_eni = branch_eni_attachments.branch_eni), TIMESTAMP 'EPOCH') ASC
     LIMIT 1) RETURNING idx, branch_eni_attachments.association_id;
     `, aws.StringValue(trunkENI.NetworkInterfaceId))

	var idx int
	var associationID string

	err := row.Scan(&idx, &associationID)
	if err == sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(errAllENIsInUse))
		return 0, errAllENIsInUse
	} else if err != nil {
		err = errors.Wrap(err, "Cannot get unused branch ENI to detach")
		span.SetStatus(traceStatusFromError(err))
		return 0, err
	}

	ec2client := ec2.New(instanceSession.Session)
	_, err = ec2client.DisassociateTrunkInterfaceWithContext(ctx, &ec2.DisassociateTrunkInterfaceInput{
		AssociationId: aws.String(associationID),
	})

	if err != nil {
		err = errors.Wrap(err, "Unable to disassociate ENI")
		span.SetStatus(traceStatusFromError(err))
		return 0, err
	}

	return idx, nil
}

func (vpcService *vpcService) ensureBranchENIPermissionV3(ctx context.Context, tx *sql.Tx, trunkENI *ec2.InstanceNetworkInterface, branchENISession *ec2wrapper.EC2Session, eni *branchENI) error {
	ctx, span := trace.StartSpan(ctx, "ensureBranchENIPermissionV3")
	defer span.End()

	if eni.accountID == aws.StringValue(trunkENI.OwnerId) {
		return nil
	}

	// This could be collapsed into a join on the above query, but for now, we wont do that
	row := tx.QueryRowContext(ctx, "SELECT COALESCE(count(*), 0) FROM eni_permissions WHERE branch_eni = $1 AND account_id = $2", eni.id, eni.accountID)
	var permissions int
	err := row.Scan(&permissions)
	if err != nil {
		err = errors.Wrap(err, "Cannot retrieve from branch ENI permissions")
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	if permissions > 0 {
		return nil
	}

	logger.G(ctx).Debugf("Creating network interface permission to allow account %s to attach branch ENI in account %s", aws.StringValue(trunkENI.OwnerId), eni.accountID)
	ec2client := ec2.New(branchENISession.Session)
	_, err = ec2client.CreateNetworkInterfacePermissionWithContext(ctx, &ec2.CreateNetworkInterfacePermissionInput{
		AwsAccountId:       trunkENI.OwnerId,
		NetworkInterfaceId: aws.String(eni.id),
		Permission:         aws.String("INSTANCE-ATTACH"),
	})

	if err != nil {
		err = errors.Wrap(err, "Cannot create network interface permission")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}

func (vpcService *vpcService) assignIPWithChangeSGOnENI(ctx context.Context, req *vpcapi.AssignIPRequestV3, s *subnet, trunkENI *ec2.InstanceNetworkInterface, instance *ec2.Instance, maxIPAddresses int) (resp *vpcapi.AssignIPResponseV3, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "assignIPWithChangeSGOnENI")
	defer span.End()

	logger.G(ctx).Debug("Trying to find existing ENI with different security groups")

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		if retErr == nil {
			retErr = tx.Commit()
			if retErr != nil {
				span.SetStatus(traceStatusFromError(err))
			}
		} else {
			_ = tx.Rollback()
		}
	}()

	// TODO: Join branch_eni_last_used to get "oldest" branch ENI
	row := tx.QueryRowContext(ctx, `
SELECT valid_branch_enis.branch_eni_id,
       valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.account_id,
       valid_branch_enis.az,
       valid_branch_enis.idx
FROM
  (SELECT branch_enis.id AS branch_eni_id,
          branch_enis.branch_eni,
          branch_enis.account_id,
          branch_enis.az,
          branch_eni_attachments.association_id,
          branch_eni_attachments.idx,
     (SELECT count(*)
      FROM assignments
      WHERE assignments.branch_eni_association = branch_eni_attachments.association_id) AS c
   FROM branch_enis
   JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
   WHERE subnet_id = $1
     AND trunk_eni = $2) valid_branch_enis
WHERE c = 0
FOR UPDATE
LIMIT 1
`, s.subnetID, aws.StringValue(trunkENI.NetworkInterfaceId))

	var branchENIID int
	var eni branchENI
	err = row.Scan(&branchENIID, &eni.id, &eni.associationID, &eni.accountID, &eni.az, &eni.idx)
	if err == sql.ErrNoRows {
		logger.G(ctx).Debug("Could not find ENI")
		span.SetStatus(traceStatusFromError(errAssignmentMethodNotPossible))
		return nil, errAssignmentMethodNotPossible
	}
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	// Update the security groups on the branch ENI
	securityGroups := req.SecurityGroupIds
	sort.Strings(securityGroups)
	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1 WHERE id = $2", pq.Array(securityGroups), branchENIID)
	if err != nil {
		err = errors.Wrap(err, "Could not update security groups in database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: eni.accountID,
		Region:    azToRegionRegexp.FindString(eni.az),
	})

	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ec2client := ec2.New(session.Session)
	_, err = ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             aws.StringSlice(securityGroups),
		NetworkInterfaceId: aws.String(eni.id),
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot modify security groups on interface")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return vpcService.assignIPsToENI(ctx, req, tx, session, s, &eni, instance, trunkENI, maxIPAddresses)
}

func (vpcService *vpcService) assignIPWithSharedENI(ctx context.Context, req *vpcapi.AssignIPRequestV3, s *subnet, trunkENI *ec2.InstanceNetworkInterface, instance *ec2.Instance, maxIPAddresses int) (resp *vpcapi.AssignIPResponseV3, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "assignIPWithSharedENI")
	defer span.End()

	logger.G(ctx).Debug("Trying to find existing ENI with same security groups")

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		if retErr == nil {
			retErr = tx.Commit()
			if retErr != nil {
				span.SetStatus(traceStatusFromError(err))
			}
		} else {
			_ = tx.Rollback()
		}
	}()

	securityGroupIDs := req.SecurityGroupIds
	sort.Strings(securityGroupIDs)
	row := tx.QueryRowContext(ctx, `
SELECT valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.account_id,
       valid_branch_enis.az,
       valid_branch_enis.idx
FROM
  (SELECT branch_enis.branch_eni,
          branch_enis.account_id,
          branch_enis.az,
          branch_eni_attachments.association_id,
          branch_eni_attachments.idx,
          branch_eni_attachments.created_at AS branch_eni_attached_at,
     (SELECT count(*)
      FROM assignments
      WHERE assignments.branch_eni_association = branch_eni_attachments.association_id) AS c
   FROM branch_enis
   JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
   WHERE subnet_id = $1
     AND trunk_eni = $2
     AND security_groups = $3 ) valid_branch_enis
WHERE c < $4
ORDER BY c DESC, branch_eni_attached_at ASC
FOR UPDATE
LIMIT 1
`, s.subnetID, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(securityGroupIDs), maxIPAddresses)

	var eni branchENI
	err = row.Scan(&eni.id, &eni.associationID, &eni.accountID, &eni.az, &eni.idx)
	if err == sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(errAssignmentMethodNotPossible))
		return nil, errAssignmentMethodNotPossible
	}
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: eni.accountID,
		Region:    azToRegionRegexp.FindString(eni.az),
	})

	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	// Otherwise continue?
	return vpcService.assignIPsToENI(ctx, req, tx, session, s, &eni, instance, trunkENI, maxIPAddresses)
}

func (vpcService *vpcService) assignIPsToENI(ctx context.Context, req *vpcapi.AssignIPRequestV3, tx *sql.Tx, session *ec2wrapper.EC2Session, subnet *subnet, eni *branchENI, instance *ec2.Instance, trunkENI *ec2.InstanceNetworkInterface, maxIPAddresses int) (*vpcapi.AssignIPResponseV3, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "assignIPsToENI")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("eni", eni.id))

	iface, err := session.GetNetworkInterfaceByID(ctx, eni.id, 100*time.Millisecond)
	if err != nil {
		err = errors.Wrap(err, "Cannot get branch ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	hasSecurityGroupSet := sets.NewString()
	for idx := range iface.Groups {
		hasSecurityGroupSet.Insert(aws.StringValue(iface.Groups[idx].GroupId))
	}

	if !hasSecurityGroupSet.Equal(sets.NewString(req.SecurityGroupIds...)) {
		err = fmt.Errorf("Branch ENI has security groups %s, when expected %s", hasSecurityGroupSet.List(), req.SecurityGroupIds)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	if s := aws.StringValue(iface.Status); s != "in-use" {
		err = fmt.Errorf("Branch ENI not in expected status, instead: %q", s)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row := tx.QueryRowContext(ctx, "INSERT INTO assignments(assignment_id, branch_eni_association) VALUES ($1, $2) RETURNING id", req.TaskId, eni.associationID)
	var assignmentID int
	err = row.Scan(&assignmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot create assignment ID")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	resp := vpcapi.AssignIPResponseV3{}
	switch ipv4req := (req.Ipv4).(type) {
	case *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation:
		resp.Ipv4Address, err = assignSpecificIPv4AddressV3(ctx, tx, session, iface, subnet, eni, maxIPAddresses, ipv4req)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	case *vpcapi.AssignIPRequestV3_Ipv4AddressRequested:
		if ipv4req.Ipv4AddressRequested {
			resp.Ipv4Address, err = assignArbitraryIPv4AddressV3(ctx, tx, session, iface, subnet, eni, maxIPAddresses)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		}
	}
	if resp.Ipv4Address != nil {
		_, err = tx.ExecContext(ctx, "UPDATE assignments SET ipv4addr = $1 WHERE id = $2", resp.Ipv4Address.Address.Address, assignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot update assignment with v4 addr")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	switch ipv6req := (req.Ipv6).(type) {
	case *vpcapi.AssignIPRequestV3_Ipv6AddressRequested:
		if ipv6req.Ipv6AddressRequested {
			resp.Ipv6Address, err = assignArbitraryIPv6AddressV3(ctx, tx, session, iface, subnet, eni, maxIPAddresses)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		}
	}

	if resp.Ipv6Address != nil {
		_, err = tx.ExecContext(ctx, "UPDATE assignments SET ipv6addr = $1 WHERE id = $2", resp.Ipv6Address.Address.Address, assignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot update assignment with v6 addr")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET last_assigned_to = now() WHERE branch_eni = $1", aws.StringValue(iface.NetworkInterfaceId))
	if err != nil {
		err = errors.Wrap(err, "Cannot update last_assigned_to")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	resp.BranchNetworkInterface = &vpcapi.NetworkInterface{
		SubnetId:           subnet.subnetID,
		AvailabilityZone:   eni.az,
		MacAddress:         aws.StringValue(iface.MacAddress),
		NetworkInterfaceId: eni.id,
		OwnerAccountId:     eni.accountID,
		VpcId:              subnet.vpcID,
	}
	resp.TrunkNetworkInterface = instanceNetworkInterface(*instance, *trunkENI)
	resp.VlanId = uint32(eni.idx)

	return &resp, nil
}

func assignArbitraryIPv6AddressV3(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, s *subnet, eni *branchENI, maxIPAddresses int) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignArbitraryIPv6AddressV3")
	defer span.End()

	usedIPAddresses := sets.NewString()
	rows, err := tx.QueryContext(ctx, "SELECT ipv6addr FROM assignments WHERE ipv6addr IS NOT NULL AND branch_eni_association = $1", eni.associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot query ipv4addrs already assigned to interface")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	for rows.Next() {
		var address string
		err = rows.Scan(&address)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan rows")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		usedIPAddresses.Insert(address)
	}

	allInterfaceIPAddresses := sets.NewString()
	for idx := range branchENI.Ipv6Addresses {
		allInterfaceIPAddresses.Insert(aws.StringValue(branchENI.Ipv6Addresses[idx].Ipv6Address))
	}

	if l := usedIPAddresses.Len(); l >= maxIPAddresses {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses already in-use", l)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	logger.G(ctx).WithField("usedIPAddresses", usedIPAddresses.List()).WithField("allInterfaceIPAddresses", allInterfaceIPAddresses.List()).Debug("Trying to assign IPv6 Address")
	unusedIPAddresses := allInterfaceIPAddresses.Difference(usedIPAddresses)

	if unusedIPAddresses.Len() > 0 {
		unusedIPv6AddressesList := unusedIPAddresses.List()

		rows, err := tx.QueryContext(ctx, "SELECT ip_address, last_seen FROM ip_last_used_v3 WHERE host(ip_address) = any($1) AND vpc_id = $2", pq.Array(unusedIPv6AddressesList), aws.StringValue(branchENI.VpcId))
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not fetch utilized IPv4 addresses from the database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		ipToTimeLastUsed := map[string]time.Time{}
		epoch := time.Time{}
		for addr := range unusedIPAddresses {
			ipToTimeLastUsed[addr] = epoch
		}
		for rows.Next() {
			var ip string
			var lastUsed time.Time
			err = rows.Scan(&ip, &lastUsed)
			if err != nil {
				err = status.Error(codes.Unknown, errors.Wrap(err, "Could not scan utilized IPv6 addresses from the database").Error())
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
			ipToTimeLastUsed[net.ParseIP(ip).String()] = lastUsed
		}

		sort.Slice(unusedIPv6AddressesList, func(i, j int) bool {
			return ipToTimeLastUsed[unusedIPv6AddressesList[i]].Before(ipToTimeLastUsed[unusedIPv6AddressesList[j]])
		})

		return &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: unusedIPv6AddressesList[0],
			},
			PrefixLength: uint32(128),
		}, nil
	}

	ipsToAssign := maxIPAddresses - allInterfaceIPAddresses.Len()
	if ipsToAssign <= 0 {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses already assigned to interface", allInterfaceIPAddresses.Len())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if ipsToAssign > batchSize {
		ipsToAssign = batchSize
	}

	assignIpv6AddressesInput := &ec2.AssignIpv6AddressesInput{
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		Ipv6AddressCount:   aws.Int64(int64(ipsToAssign)),
	}

	ec2client := ec2.New(session.Session)
	output, err := ec2client.AssignIpv6AddressesWithContext(ctx, assignIpv6AddressesInput)
	if err != nil {
		err = ec2wrapper.HandleEC2Error(err, span)
		return nil, err
	}

	return &vpcapi.UsableAddress{
		Address: &vpcapi.Address{
			Address: aws.StringValue(output.AssignedIpv6Addresses[0]),
		},
		PrefixLength: uint32(64),
	}, nil
}

func assignArbitraryIPv4AddressV3(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, s *subnet, eni *branchENI, maxIPAddresses int) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignArbitraryIPv4Address")
	defer span.End()
	_, ipnet, err := net.ParseCIDR(s.cidr)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse cidr %s", s.cidr)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	prefixlength, _ := ipnet.Mask.Size()

	usedIPAddresses := sets.NewString()
	rows, err := tx.QueryContext(ctx, "SELECT ipv4addr FROM assignments WHERE ipv4addr IS NOT NULL AND branch_eni_association = $1", eni.associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot query ipv4addrs already assigned to interface")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	for rows.Next() {
		var address string
		err = rows.Scan(&address)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan rows")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		usedIPAddresses.Insert(address)
	}

	allInterfaceIPAddresses := sets.NewString()
	for idx := range branchENI.PrivateIpAddresses {
		allInterfaceIPAddresses.Insert(aws.StringValue(branchENI.PrivateIpAddresses[idx].PrivateIpAddress))
	}

	if l := usedIPAddresses.Len(); l >= maxIPAddresses {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses already in-use", l)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	logger.G(ctx).WithField("usedIPAddresses", usedIPAddresses.List()).WithField("allInterfaceIPAddresses", allInterfaceIPAddresses.List()).Debug("Trying to assign IP Address")
	unusedIPAddresses := allInterfaceIPAddresses.Difference(usedIPAddresses)

	if unusedIPAddresses.Len() > 0 {
		unusedIPv4AddressesList := unusedIPAddresses.List()

		rows, err := tx.QueryContext(ctx, "SELECT ip_address, last_seen FROM ip_last_used_v3 WHERE host(ip_address) = any($1) AND vpc_id = $2", pq.Array(unusedIPv4AddressesList), aws.StringValue(branchENI.VpcId))
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not fetch utilized IPv4 addresses from the database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		ipToTimeLastUsed := map[string]time.Time{}
		epoch := time.Time{}
		for addr := range unusedIPAddresses {
			ipToTimeLastUsed[addr] = epoch
		}
		for rows.Next() {
			var ip string
			var lastUsed time.Time
			err = rows.Scan(&ip, &lastUsed)
			if err != nil {
				err = status.Error(codes.Unknown, errors.Wrap(err, "Could not scan utilized IPv4 addresses from the database").Error())
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
			ipToTimeLastUsed[net.ParseIP(ip).String()] = lastUsed
		}

		sort.Slice(unusedIPv4AddressesList, func(i, j int) bool {
			return ipToTimeLastUsed[unusedIPv4AddressesList[i]].Before(ipToTimeLastUsed[unusedIPv4AddressesList[j]])
		})

		return &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: unusedIPv4AddressesList[0],
			},
			PrefixLength: uint32(prefixlength),
		}, nil
	}

	ipsToAssign := maxIPAddresses - allInterfaceIPAddresses.Len()
	if ipsToAssign <= 0 {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses already assigned to interface", allInterfaceIPAddresses.Len())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if ipsToAssign > batchSize {
		ipsToAssign = batchSize
	}

	assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             branchENI.NetworkInterfaceId,
		SecondaryPrivateIpAddressCount: aws.Int64(int64(ipsToAssign)),
	}

	ec2client := ec2.New(session.Session)
	output, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, assignPrivateIPAddressesInput)
	if err != nil {
		err = ec2wrapper.HandleEC2Error(err, span)
		return nil, err
	}

	newPrivateAddresses := make([]string, len(output.AssignedPrivateIpAddresses))
	for idx := range output.AssignedPrivateIpAddresses {
		newPrivateAddresses[idx] = aws.StringValue(output.AssignedPrivateIpAddresses[idx].PrivateIpAddress)
	}

	logger.G(ctx).WithField("newPrivateAddresses", newPrivateAddresses).Debug("Trying to insert new IPs")
	_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used_v3(ip_address, last_seen, vpc_id) (SELECT unnest($1::text[]):: inet AS ip, now(), $2) ON CONFLICT (vpc_id, ip_address) DO UPDATE SET last_seen = now()", pq.Array(newPrivateAddresses), aws.StringValue(branchENI.VpcId))
	if err != nil {
		err = errors.Wrap(err, "Cannot update ip_last_used_v3 table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &vpcapi.UsableAddress{
		Address: &vpcapi.Address{
			Address: aws.StringValue(output.AssignedPrivateIpAddresses[0].PrivateIpAddress),
		},
		PrefixLength: uint32(prefixlength),
	}, nil
}

func (vpcService *vpcService) UnassignIPV3(ctx context.Context, req *vpcapi.UnassignIPRequestV3) (resp *vpcapi.UnassignIPResponseV3, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "UnassignIPV3")
	defer span.End()

	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT ip_addresses.ip_address,
       ip_addresses.home_eni,
       branch_enis.branch_eni,
       branch_enis.account_id,
       branch_enis.az 
FROM assignments
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
JOIN ip_addresses ON assignments.ipv4addr = ip_addresses.ip_address AND branch_enis.subnet_id = ip_addresses.subnet_id
WHERE assignment_id = $1
`, req.TaskId)
	var ipAddress, homeENI, branchENI, accountID, az string
	err = row.Scan(&ipAddress, &homeENI, &branchENI, &accountID, &az)
	if err == nil {
		session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: azToRegionRegexp.FindString(az)})
		if err != nil {
			err = errors.Wrap(err, "Cannot get AWS session")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		_, err = session.UnassignPrivateIPAddresses(ctx, ec2.UnassignPrivateIpAddressesInput{
			NetworkInterfaceId: aws.String(branchENI),
			PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
		})
		// TODO: If the IP address has already been assigned, it's actually "okay"
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() != invalidParameterValue && strings.HasSuffix(awsErr.Message(), "Some of the specified addresses are not assigned to interface") {
				return nil, ec2wrapper.HandleEC2Error(err, span)
			}
		} else if err != nil {
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}

		_, err = session.AssignPrivateIPAddresses(ctx, ec2.AssignPrivateIpAddressesInput{
			NetworkInterfaceId: aws.String(homeENI),
			PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
		})
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() != invalidParameterValue {
				return nil, ec2wrapper.HandleEC2Error(err, span)
			}
		} else if err != nil {
			logger.G(ctx).WithError(err).Error("Unable to relocate IP address back to home ENI")
		}
	} else if err != sql.ErrNoRows {
		err = errors.Wrap(err, "Cannot query assignment if static address from database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1 RETURNING assignments.ipv4addr, assignments.ipv6addr, assignments.branch_eni_association", req.TaskId)
	var ipv4, ipv6 sql.NullString
	var association string
	err = row.Scan(&ipv4, &ipv6, &association)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not delete assignment from database").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT vpc_id FROM branch_enis JOIN branch_eni_attachments ON branch_eni_attachments.branch_eni = branch_enis.branch_eni WHERE branch_eni_attachments.association_id = $1", association)
	var vpcID string
	err = row.Scan(&vpcID)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not get VPC ID from database").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	if ipv4.Valid {
		_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used_v3(ip_address, vpc_id, last_seen) VALUES($1, $2, now()) ON CONFLICT(ip_address, vpc_id) DO UPDATE SET last_seen = now()", ipv4.String, vpcID)
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not update IPv4 last used in database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	if ipv6.Valid {
		_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used_v3(ip_address, vpc_id, last_seen) VALUES($1, $2, now()) ON CONFLICT(ip_address, vpc_id) DO UPDATE SET last_seen = now()", ipv6.String, vpcID)
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not update IPv6 last used in database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO branch_eni_last_used(branch_eni, last_used) VALUES ((SELECT branch_eni FROM branch_eni_attachments WHERE association_id = $1), now()) ON CONFLICT (branch_eni) DO UPDATE SET last_used = now()", association)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not update branch eni last used in database").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not commit").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &vpcapi.UnassignIPResponseV3{}, nil
}

func assignSpecificIPv4AddressV3(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, s *subnet, eni *branchENI, maxIPAddresses int, alloc *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignSpecificIPv4AddressV3")

	_, ipnet, err := net.ParseCIDR(s.cidr)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse cidr %s", s.cidr)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	prefixlength, _ := ipnet.Mask.Size()

	row := tx.QueryRowContext(ctx, "SELECT ip_address FROM ip_addresses WHERE id = $1 FOR UPDATE", alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid)
	var ip string
	err = row.Scan(&ip)
	if err == sql.ErrNoRows {
		err = errors.Wrapf(err, "Could not find allocation: %s", alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid)
		span.SetStatus(trace.Status{Code: trace.StatusCodeNotFound, Message: err.Error()})
		return nil, status.Error(codes.NotFound, err.Error())
	}

	if err != nil {
		err = errors.Wrap(err, "Could not fetch allocations from database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ec2client := ec2.New(session.Session)

	assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddresses: aws.StringSlice([]string{ip}),
		AllowReassignment:  aws.Bool(true),
	}

	// There's one error condition here which is kind of nasty and unaddressed (at least for now)
	// if there have been 50 users of the interface, and we come along, we'll blow out the max ip addresses
	// for the interface.
	//
	// A todo is to clean up / GC the interface prior to doing this assignment.
	output, err := ec2client.AssignPrivateIpAddressesWithContext(ctx, assignPrivateIPAddressesInput)
	if err != nil {
		err = ec2wrapper.HandleEC2Error(err, span)
		return nil, err
	}
	return &vpcapi.UsableAddress{
		Address: &vpcapi.Address{
			Address: aws.StringValue(output.AssignedPrivateIpAddresses[0].PrivateIpAddress),
		},
		PrefixLength: uint32(prefixlength),
	}, nil
}
