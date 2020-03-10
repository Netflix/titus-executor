package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

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
	invalidParameterValue        = "InvalidParameterValue"
	invalidAssociationIDNotFound = "InvalidAssociationID.NotFound"
)

var (
	errAllENIsInUse                = errors.New("All ENIs in use, cannot deallocate any ENIs")
	errOnlyStaticAddressesAssigned = errors.New("We only found static IP addresses on this interface, and there are no free dynamic IPs")
	errZeroAddresses               = errors.New("Zero addresses in Elastic IP list")
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
	region    string
}

func (s *subnet) key() string {
	return fmt.Sprintf("%s_%s_%s", s.region, s.accountID, s.subnetID)
}

func (s *subnet) String() string {
	return fmt.Sprintf("Subnet{id=%s, az=%s, vpc=%s, account=%s}", s.vpcID, s.az, s.vpcID, s.accountID)
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
		row = tx.QueryRowContext(ctx, `
SELECT subnets.az,
       subnets.vpc_id,
       subnets.account_id,
       subnets.subnet_id,
       subnets.cidr,
       availability_zones.region
FROM subnets
JOIN account_mapping ON subnets.subnet_id = account_mapping.subnet_id
JOIN availability_zones ON subnets.az = availability_zones.zone_name AND subnets.account_id = availability_zones.account_id
WHERE subnets.account_id = $1
  AND subnets.az = $2
`,
			accountID, az)
	} else {
		row = tx.QueryRowContext(ctx, `
SELECT subnets.az,
       subnets.vpc_id,
       subnets.account_id,
       subnet_id,
       CIDR,
       availability_zones.region
FROM subnets
JOIN availability_zones ON subnets.az = availability_zones.zone_name AND subnets.account_id = availability_zones.account_id
WHERE subnets.az = $1
  AND subnets.subnet_id = any($2)
LIMIT 1
`, az, pq.Array(subnetIDs))
	}
	ret := subnet{}
	err = row.Scan(&ret.az, &ret.vpcID, &ret.accountID, &ret.subnetID, &ret.cidr, &ret.region)
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

	if req.InstanceIdentity == nil {
		err := status.Error(codes.InvalidArgument, "Instance ID is not specified")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

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

	if len(req.SecurityGroupIds) == 0 {
		err := status.Error(codes.InvalidArgument, "No security groups specified")
		tracehelpers.SetStatus(err, span)
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
	if err == nil && resp != nil {
		return resp, err
	}

	if err != nil {
		return nil, err
	}

	resp, err = vpcService.assignIPWithChangeSGOnENI(ctx, req, subnet, trunkENI, instance, maxIPAddresses)
	if err == nil && resp != nil {
		return resp, err
	}

	if err != nil {
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

	var eni branchENI

	sort.Strings(wantedSecurityGroupsIDs)
	row := tx.QueryRowContext(ctx, `
	SELECT branch_eni, az, account_id
	FROM branch_enis
	WHERE branch_eni NOT IN
		(SELECT branch_eni
		 FROM branch_eni_attachments)
	  AND subnet_id = $1
	  AND security_groups = $2
	ORDER BY RANDOM()
	FOR
	NO KEY UPDATE SKIP LOCKED
	LIMIT 1
	`, subnetID, pq.Array(wantedSecurityGroupsIDs))
	err := row.Scan(&eni.id, &eni.az, &eni.accountID)
	if err == nil {
		return &eni, nil
	} else if err != sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, `
	SELECT branch_eni, az, account_id
	FROM branch_enis
	WHERE branch_eni NOT IN
		(SELECT branch_eni
		 FROM branch_eni_attachments)
	  AND subnet_id = $1
	ORDER BY RANDOM()
	FOR
	NO KEY UPDATE SKIP LOCKED
	LIMIT 1
	`, subnetID)
	err = row.Scan(&eni.id, &eni.az, &eni.accountID)
	if err == nil {
		_, err = session.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
			Groups:             aws.StringSlice(wantedSecurityGroupsIDs),
			NetworkInterfaceId: aws.String(eni.id),
		})
		if err != nil {
			err = errors.Wrap(err, "Cannot modify security groups on interface")
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}

		_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1 WHERE branch_eni = $2", pq.Array(wantedSecurityGroupsIDs), eni.id)
		if err != nil {
			err = errors.Wrap(err, "Cannot update security groups in database on branch ENI")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}

		return &eni, nil
	} else if err != sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	iface, err := vpcService.createBranchENI(ctx, tx, session, subnetID, wantedSecurityGroupsIDs)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &branchENI{
		id:        aws.StringValue(iface.NetworkInterfaceId),
		az:        aws.StringValue(iface.AvailabilityZone),
		accountID: aws.StringValue(iface.OwnerId),
	}, nil
}

func (vpcService *vpcService) assignIPWithAddENI(ctx context.Context, req *vpcapi.AssignIPRequestV3, instanceSession *ec2wrapper.EC2Session, s *subnet, trunkENI *ec2.InstanceNetworkInterface, instance *ec2.Instance, maxIPAddresses int) (resp *vpcapi.AssignIPResponseV3, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "assignIPWithAddENI")
	defer span.End()

	logger.G(ctx).Debug("Trying to add new ENI attachment to instance")
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
		attachmentIdx, _, _, err = vpcService.detachBranchENI(ctx, tx, instanceSession, aws.StringValue(trunkENI.NetworkInterfaceId))
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

	logger.G(ctx).WithField("idx", attachmentIdx).Debug("Attaching new branch ENI")
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
	err = vpcService.ensureBranchENIPermissionV3(ctx, tx, aws.StringValue(trunkENI.OwnerId), branchENISession, eni)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	associationID, err := vpcService.associateNetworkInterface(ctx, tx, instanceSession, association{
		branchENI: eni.id,
		trunkENI:  aws.StringValue(trunkENI.NetworkInterfaceId),
	}, attachmentIdx)
	if err != nil {
		if errors.Is(err, &persistentError{}) {
			logger.G(ctx).WithError(err).Error("Received persistent error, committing current state, and returning error")
			err2 := tx.Commit()
			if err2 != nil {
				logger.G(ctx).WithError(err2).Error("Failed to commit transaction early due to persistent AWS error")
			}
			tracehelpers.SetStatus(err, span)
			return nil, err
		}

		err = errors.Wrap(err, "Cannot associate trunk interface with branch ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	eni.idx = attachmentIdx
	eni.associationID = *associationID

	return vpcService.assignIPsToENI(ctx, req, tx, branchENISession, s, eni, instance, trunkENI, maxIPAddresses)
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
	// This over-locks all the branch ENIs attached to the trunk ENI.
	// TODO(Fix locking)
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
     AND trunk_eni = $2  FOR NO KEY UPDATE OF branch_enis, branch_eni_attachments) valid_branch_enis
WHERE c = 0
FOR NO KEY UPDATE
LIMIT 1
`, s.subnetID, aws.StringValue(trunkENI.NetworkInterfaceId))

	var branchENIID int
	var eni branchENI
	err = row.Scan(&branchENIID, &eni.id, &eni.associationID, &eni.accountID, &eni.az, &eni.idx)
	if err == sql.ErrNoRows {
		logger.G(ctx).Debug("Could not find ENI")
		span.SetStatus(trace.Status{Code: trace.StatusCodeFailedPrecondition, Message: "Assignment method not possible"})
		return nil, nil
	}
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	// Update the security groups on the branch ENI
	securityGroups := req.SecurityGroupIds
	sort.Strings(securityGroups)
	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1, modified_at = now() WHERE id = $2", pq.Array(securityGroups), branchENIID)
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

	_, err = session.ModifyNetworkInterfaceAttribute(ctx, ec2.ModifyNetworkInterfaceAttributeInput{
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
     AND security_groups = $3 FOR NO KEY UPDATE OF branch_enis, branch_eni_attachments ) valid_branch_enis
WHERE c < $4
ORDER BY c DESC, branch_eni_attached_at ASC
FOR NO KEY UPDATE
LIMIT 1
`, s.subnetID, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(securityGroupIDs), maxIPAddresses)

	var eni branchENI
	err = row.Scan(&eni.id, &eni.associationID, &eni.accountID, &eni.az, &eni.idx)
	if err == sql.ErrNoRows {
		span.SetStatus(trace.Status{Code: trace.StatusCodeFailedPrecondition, Message: "Assignment method not possible"})
		return nil, nil
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

	row := tx.QueryRowContext(ctx, "SELECT security_groups FROM branch_enis WHERE branch_eni = $1", eni.id)
	var dbSecurityGroups []string
	err := row.Scan(pq.Array(&dbSecurityGroups))
	if err != nil {
		err = errors.Wrap(err, "Cannot query assigned SGs to ENI in database")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if !sets.NewString(dbSecurityGroups...).Equal(sets.NewString(req.SecurityGroupIds...)) {
		err = fmt.Errorf("Database has security groups %s, when expected %s", dbSecurityGroups, req.SecurityGroupIds)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

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

	row = tx.QueryRowContext(ctx, "INSERT INTO assignments(assignment_id, branch_eni_association) VALUES ($1, $2) RETURNING id", req.TaskId, eni.associationID)
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
		resp.Ipv4Address, err = assignSpecificIPv4AddressV3(ctx, tx, session, iface, subnet, eni, maxIPAddresses, ipv4req, req.TaskId)
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

		// TODO(The user will get no public IP if they don't assign an IPv4 IP
		switch eip := (req.ElasticAddress).(type) {
		case *vpcapi.AssignIPRequestV3_ElasticAdddresses:
			resp.ElasticAddress, err = assignElasticAddressesBasedOnIDs(ctx, tx, session, iface, resp.Ipv4Address, eip.ElasticAdddresses, req.TaskId)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		case *vpcapi.AssignIPRequestV3_GroupName:
			resp.ElasticAddress, err = assignElasticAddressesBasedOnGroupName(ctx, tx, session, iface, resp.Ipv4Address, eip.GroupName, req.TaskId)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		case *vpcapi.AssignIPRequestV3_Empty:
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

func assignElasticAddressesBasedOnIDs(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, ipv4Address *vpcapi.UsableAddress, elasticAddressSet *vpcapi.ElasticAddressSet, assignmentID string) (*vpcapi.ElasticAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignElasticAddressesBasedOnIDs")
	defer span.End()

	borderGroup, err := getBorderGroupForENI(ctx, tx, branchENI)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	addresses := elasticAddressSet.ElasticAddresses
	if len(addresses) == 0 {
		span.SetStatus(traceStatusFromError(errZeroAddresses))
		return nil, errZeroAddresses
	}

	row := tx.QueryRowContext(ctx, `
SELECT allocation_id, public_ip
FROM elastic_ips
WHERE account_id = $1
  AND allocation_id NOT IN
    (SELECT elastic_ip_allocation_id
     FROM elastic_ip_attachments)
  AND network_border_group = $2
  AND allocation_id = any($3)
LIMIT 1
FOR
UPDATE OF elastic_ips
`, aws.StringValue(branchENI.OwnerId), borderGroup, pq.Array(addresses))
	var allocationID, publicIP string
	err = row.Scan(&allocationID, &publicIP)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("No EIP in list %s free", addresses)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	} else if err != nil {
		err = errors.Wrap(err, "Cannot query for free elastic IPs")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "INSERT INTO elastic_ip_attachments(elastic_ip_allocation_id, assignment_id) VALUES ($1, $2) RETURNING id",
		allocationID, assignmentID)
	var id int
	err = row.Scan(&id)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert into elastic_ip_attachments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ec2client := ec2.New(session.Session)
	associateAddressOutput, err := ec2client.AssociateAddress(&ec2.AssociateAddressInput{
		AllocationId:       aws.String(allocationID),
		AllowReassociation: aws.Bool(true),
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddress:   aws.String(ipv4Address.Address.Address),
	})
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = tx.ExecContext(ctx, "UPDATE elastic_ip_attachments SET association_id = $1 WHERE id = $2", aws.StringValue(associateAddressOutput.AssociationId), id)
	if err != nil {
		err = errors.Wrap(err, "Unable to update elastic_ip_attachments table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &vpcapi.ElasticAddress{
		AllocationId:   allocationID,
		Ip:             publicIP,
		AssociationdId: aws.StringValue(associateAddressOutput.AssociationId),
	}, nil
}

func assignElasticAddressesBasedOnGroupName(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, ipv4Address *vpcapi.UsableAddress, groupName, assignmentID string) (*vpcapi.ElasticAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignElasticAddressesBasedOnGroupName")
	defer span.End()

	borderGroup, err := getBorderGroupForENI(ctx, tx, branchENI)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row := tx.QueryRowContext(ctx, `
SELECT allocation_id, public_ip
FROM elastic_ips
WHERE account_id = $1
  AND allocation_id NOT IN
    (SELECT elastic_ip_allocation_id
     FROM elastic_ip_attachments)
  AND network_border_group = $2
  AND tags->>'titus_vpc_pool' = $3
LIMIT 1
FOR
UPDATE of elastic_ips
`, aws.StringValue(branchENI.OwnerId), borderGroup, groupName)
	var allocationID, publicIP string
	err = row.Scan(&allocationID, &publicIP)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("No EIP in group %s free in network border group %s", groupName, borderGroup)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	} else if err != nil {
		err = errors.Wrap(err, "Cannot query for free elastic IPs")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "INSERT INTO elastic_ip_attachments(elastic_ip_allocation_id, assignment_id) VALUES ($1, $2) RETURNING id",
		allocationID, assignmentID)
	var id int
	err = row.Scan(&id)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert into elastic_ip_attachments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ec2client := ec2.New(session.Session)
	associateAddressOutput, err := ec2client.AssociateAddress(&ec2.AssociateAddressInput{
		AllocationId:       aws.String(allocationID),
		AllowReassociation: aws.Bool(true),
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddress:   aws.String(ipv4Address.Address.Address),
	})
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = tx.ExecContext(ctx, "UPDATE elastic_ip_attachments SET association_id = $1 WHERE id = $2", aws.StringValue(associateAddressOutput.AssociationId), id)
	if err != nil {
		err = errors.Wrap(err, "Unable to update elastic_ip_attachments table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &vpcapi.ElasticAddress{
		AllocationId:   allocationID,
		Ip:             publicIP,
		AssociationdId: aws.StringValue(associateAddressOutput.AssociationId),
	}, nil
}

func getBorderGroupForENI(ctx context.Context, tx *sql.Tx, eni *ec2.NetworkInterface) (string, error) {
	ctx, span := trace.StartSpan(ctx, "getBorderGroupForENI")
	defer span.End()

	az := aws.StringValue(eni.AvailabilityZone)
	ownerID := aws.StringValue(eni.OwnerId)
	row := tx.QueryRowContext(ctx, "SELECT network_border_group FROM availability_zones WHERE zone_name = $1 AND account_id = $2", az, ownerID)
	var borderGroup string
	err := row.Scan(&borderGroup)
	if err != nil {
		err = errors.Wrapf(err, "Cannot get border group for AZ %s, and owner ID %s", az, ownerID)
		span.SetStatus(traceStatusFromError(err))
		return "", err
	}

	return borderGroup, nil
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
		err = status.Errorf(codes.FailedPrecondition, "%d IPv6 addresses already in-use", l)
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

		rows, err := tx.QueryContext(ctx, "SELECT ip_address FROM ip_addresses WHERE host(ip_address) = any($1) AND subnet_id = $2", pq.Array(unusedIPv4AddressesList), aws.StringValue(branchENI.SubnetId))
		if err != nil {
			err = errors.Wrap(err, "Cannot fetch statically assigned IP addresses")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		for rows.Next() {
			var staticIPAddress string
			err = rows.Scan(&staticIPAddress)
			if err != nil {
				err = errors.Wrap(err, "Cannot scan statically assigned IP address")
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
			unusedIPAddresses.Delete(staticIPAddress)
		}
	}

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
	newPrivateAddressesSet := sets.NewString(newPrivateAddresses...)

	logger.G(ctx).WithField("newPrivateAddresses", newPrivateAddresses).Debug("Trying to insert new IPs")
	_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used_v3(ip_address, last_seen, vpc_id) (SELECT unnest($1::text[]):: inet AS ip, now(), $2) ON CONFLICT (vpc_id, ip_address) DO UPDATE SET last_seen = now()", pq.Array(newPrivateAddresses), aws.StringValue(branchENI.VpcId))
	if err != nil {
		err = errors.Wrap(err, "Cannot update ip_last_used_v3 table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	rows, err = tx.QueryContext(ctx, "SELECT ip_address FROM ip_addresses WHERE host(ip_address) = any($1) AND subnet_id = $2", pq.Array(newPrivateAddresses), aws.StringValue(branchENI.SubnetId))
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch statically assigned IP addresses")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	for rows.Next() {
		var staticIPAddress string
		err = rows.Scan(&staticIPAddress)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan statically assigned IP address")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		newPrivateAddressesSet.Delete(staticIPAddress)
	}

	if newPrivateAddressesSet.Len() == 0 {
		span.SetStatus(traceStatusFromError(errOnlyStaticAddressesAssigned))
		return nil, errOnlyStaticAddressesAssigned
	}

	return &vpcapi.UsableAddress{
		Address: &vpcapi.Address{
			Address: newPrivateAddressesSet.UnsortedList()[0],
		},
		PrefixLength: uint32(prefixlength),
	}, nil
}

func (vpcService *vpcService) unassignStaticAddress(ctx context.Context, assignmentID string) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "unassignStaticAddress")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT branch_enis.branch_eni,
       branch_enis.az,
       branch_enis.account_id,
       ip_address,
       home_eni
FROM ip_address_attachments
JOIN ip_addresses ON ip_address_attachments.ip_address_uuid = ip_addresses.id
JOIN assignments ON ip_address_attachments.assignment_id = assignments.assignment_id
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE ip_address_attachments.assignment_id = $1
`, assignmentID)
	var branchENI, az, accountID, ipAddress, homeEni string
	err = row.Scan(&branchENI, &az, &accountID, &ipAddress, &homeEni)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot query assignment for static addresses")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: azToRegionRegexp.FindString(az)})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	ec2client := ec2.New(session.Session)
	_, err = ec2client.AssignPrivateIpAddressesWithContext(ctx, &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(branchENI),
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
		AllowReassignment:  aws.Bool(true),
	})
	if err != nil {
		return false, ec2wrapper.HandleEC2Error(err, span)
	}

	// This will automagically cascade and delete the static attachment as well
	_, err = tx.ExecContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1", assignmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot delete assignment from assignments table")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	err = tx.Commit()

	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	return true, nil
}

func (vpcService *vpcService) unassignElasticAddress(ctx context.Context, assignmentID string) error {
	ctx, span := trace.StartSpan(ctx, "unassignElasticAddress")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT elastic_ip_attachments.id,
       account_id,
       region,
       association_id
FROM elastic_ip_attachments
JOIN elastic_ips ON elastic_ip_attachments.elastic_ip_allocation_id = elastic_ips.allocation_id
WHERE elastic_ip_attachments.assignment_id = $1
`, assignmentID)
	var id int
	var accountID, region, associationID string
	err = row.Scan(&id, &accountID, &region, &associationID)
	if err == sql.ErrNoRows {
		return nil
	}

	if err != nil {
		err = errors.Wrap(err, "Could not scan elastic IP associations")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	ec2client := ec2.New(session.Session)
	_, err = ec2client.DisassociateAddressWithContext(ctx, &ec2.DisassociateAddressInput{
		AssociationId: aws.String(associationID),
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() != invalidAssociationIDNotFound {
				return ec2wrapper.HandleEC2Error(err, span)
			}
		} else {
			return ec2wrapper.HandleEC2Error(err, span)
		}
	}

	// This will automagically cascade and delete the static attachment as well
	_, err = tx.ExecContext(ctx, "DELETE FROM elastic_ip_attachments WHERE id = $1", id)
	if err != nil {
		err = errors.Wrap(err, "Cannot delete elastic ip attachment from elastic ip attachments table")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	err = tx.Commit()

	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}

func (vpcService *vpcService) UnassignIPV3(ctx context.Context, req *vpcapi.UnassignIPRequestV3) (resp *vpcapi.UnassignIPResponseV3, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "UnassignIPV3")
	defer span.End()

	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	if unassigned, err := vpcService.unassignStaticAddress(ctx, req.TaskId); err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	} else if unassigned {
		return &vpcapi.UnassignIPResponseV3{}, nil
	}

	if err := vpcService.unassignElasticAddress(ctx, req.TaskId); err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1 RETURNING assignments.ipv4addr, assignments.ipv6addr, assignments.branch_eni_association", req.TaskId)
	var ipv4, ipv6 sql.NullString
	var association string
	err = row.Scan(&ipv4, &ipv6, &association)
	if err == nil {
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
	} else if err == sql.ErrNoRows {
		err = status.Errorf(codes.NotFound, "Could not find assignment ID %q in the database", req.TaskId)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	} else {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not delete assignment from database").Error())
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

func assignSpecificIPv4AddressV3(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, s *subnet, eni *branchENI, maxIPAddresses int, alloc *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation, assignmentID string) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignSpecificIPv4AddressV3")

	_, ipnet, err := net.ParseCIDR(s.cidr)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse cidr %s", s.cidr)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	prefixlength, _ := ipnet.Mask.Size()

	row := tx.QueryRowContext(ctx, "SELECT id, ip_address, subnet_id FROM ip_addresses WHERE id = $1 FOR UPDATE", alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid)
	var id, ip, subnetID string
	err = row.Scan(&id, &ip, &subnetID)
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

	if subnetID != aws.StringValue(branchENI.SubnetId) {
		err = fmt.Errorf("Branch ENI in subnet %s, but IP allocation in subnet %s", aws.StringValue(branchENI.SubnetId), subnetID)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO ip_address_attachments(ip_address_uuid, assignment_id) VALUES ($1, $2)", id, assignmentID)
	if err != nil {
		err = errors.Wrap(err, "Could not insert ip address attachment into database")
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
