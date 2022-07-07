package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/db"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"github.com/m7shapan/cidr"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	invalidAssociationIDNotFound = "InvalidAssociationID.NotFound"
	assignTimeout                = 5 * time.Minute
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

type branchENI struct {
	intid         int64
	id            string
	az            string
	associationID string
	accountID     string
	idx           int
}

func (vpcService *vpcService) getLeastUsedSubnet(ctx context.Context, az, accountID string, subnetIDs []string) (*data.Subnet, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "getLeastUsedSubnet")
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

	subnet, err := db.GetLeastUsedSubnet(ctx, tx, az, accountID, subnetIDs)
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch subnet ID from database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return subnet, nil
}

func (vpcService *vpcService) getStaticAllocation(ctx context.Context, alloc *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation) (*data.StaticAllocation, error) {
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

	staticAllocation, err := db.GetStaticAllocationByID(ctx, tx, alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Cannot read static allocation").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	return staticAllocation, nil
}

func (vpcService *vpcService) fetchIdempotentAssignment(ctx context.Context, taskID string, deleteUnfinishedAssignment bool) (*vpcapi.AssignIPResponseV3, error) {
	ctx, span := trace.StartSpan(ctx, "fetchIdempotentAssignment")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("taskID", taskID),
		trace.BoolAttribute("deleteUnfinishedAssignment", deleteUnfinishedAssignment),
	)

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot start transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	assignment, completed, err := db.GetAndLockAssignmentByTaskID(ctx, tx, taskID)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		err = errors.Wrap(err, "Unable to query assignments")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if !completed {
		if deleteUnfinishedAssignment {
			// Delete the assignment
			_, err = tx.ExecContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1", taskID)
			if err != nil {
				err = errors.Wrap(err, "Cannot delete incomplete assignment")
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
			err = tx.Commit()
			if err != nil {
				err = errors.Wrap(err, "Cannot commit transaction after deleting assignment")
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
		} else {
			err = status.Errorf(codes.FailedPrecondition, "Assignment for task %s is not completed", taskID)
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		return nil, nil
	}

	_, err = tx.ExecContext(ctx, "SET TRANSACTION READ ONLY")
	if err != nil {
		err = errors.Wrap(err, "Could not set transaction read only")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	// TODO(Sargun): Implement transition assignment logic
	resp := vpcapi.AssignIPResponseV3{
		BranchNetworkInterface: &vpcapi.NetworkInterface{
			// NetworkInterfaceAttachment is not used in assignipv3
			NetworkInterfaceAttachment: nil,
		},
		TrunkNetworkInterface: &vpcapi.NetworkInterface{
			// NetworkInterfaceAttachment is not used in assignipv3
			NetworkInterfaceAttachment: nil,
		},
		VlanId: uint32(assignment.VlanID),
		Bandwidth: &vpcapi.AssignIPResponseV3_Bandwidth{
			Bandwidth: assignment.Bandwidth,
			Burst:     assignment.Ceil,
		},
	}

	resp.Routes = vpcService.getRoutes(ctx, assignment.SubnetID.String)

	resp.BranchNetworkInterface, err = db.GetBranchENI(ctx, tx, assignment.BranchENI)
	if err != nil {
		err = errors.Wrap(err, "Cannot get branch ENI from DB")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	resp.TrunkNetworkInterface, err = db.GetTrunkENI(ctx, tx, assignment.TrunkENI)
	if err != nil {
		err = errors.Wrap(err, "Cannot get trunk ENI from DB")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if assignment.IPv4Addr.Valid {
		_, ipnet, err := db.GetCIDRBySubnet(ctx, tx, resp.BranchNetworkInterface.SubnetId)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		ones, _ := ipnet.Mask.Size()
		resp.Ipv4Address = &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: assignment.IPv4Addr.String,
			},
			PrefixLength: uint32(ones),
		}
	}

	if assignment.IPv6Addr.Valid {
		resp.Ipv6Address = &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: assignment.IPv6Addr.String,
			},
			PrefixLength: 128,
		}
	}

	resp.ElasticAddress, err = db.GetElasticAddressByTaskID(ctx, tx, taskID)
	if err != nil && err != sql.ErrNoRows {
		err = errors.Wrap(err, "Could not get elastic IP from DB")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	resp.ClassId, err = db.GetClassIDByAssignmentID(ctx, tx, assignment.ID)
	if err != nil {
		err = errors.Wrapf(err, "Cannot get HTB class ID for assignment %d from DB", assignment.ID)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction after reading assignment")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &resp, nil
}

func (vpcService *vpcService) GetAssignment(ctx context.Context, req *vpcapi.GetAssignmentRequest) (*vpcapi.GetAssignmentResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, assignTimeout)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GetAssignment")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	var err error
	ret := vpcapi.GetAssignmentResponse{}
	ret.Assignment, err = vpcService.fetchIdempotentAssignment(ctx, req.TaskId, false)
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch previous assignment")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if ret.Assignment == nil {
		err = status.Errorf(codes.NotFound, "Could not find previous assignment")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &ret, nil
}

// Returns an error if the request is invalid. Returns nil otherwise.
func validateAssignIPV3Request(req *vpcapi.AssignIPRequestV3) error {
	if req.InstanceIdentity == nil || req.InstanceIdentity.InstanceID == "" {
		return status.Error(codes.InvalidArgument, "Instance ID is not specified")
	}

	if req.TaskId == "" {
		return status.Error(codes.InvalidArgument, "Task ID is not specified")
	}

	if len(req.SecurityGroupIds) == 0 {
		return status.Error(codes.InvalidArgument, "No security groups specified")
	}
	return nil
}

func (vpcService *vpcService) AssignIPV3(ctx context.Context, req *vpcapi.AssignIPRequestV3) (*vpcapi.AssignIPResponseV3, error) {
	// 1. Get the trunk ENI
	// 2. Choose the subnet we're "scheduling" into
	// 3. Check if there are any branch ENIs already attached to the trunk ENI with the subnet + security groups wanted, and have fewer than 50 assignments (for share)
	// 4. Check if there are any branch ENIs with the subnet with 0 allocations (FOR UPDATE), set the security groups, and then lock the ENI, and so on.
	// 5. Attach an ENI that fulfills the requirements
	ctx, cancel := context.WithTimeout(ctx, assignTimeout)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssignIPv3")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	err := validateAssignIPV3Request(req)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	ctx = logger.WithFields(ctx, map[string]interface{}{
		"instance": req.InstanceIdentity.InstanceID,
		"taskID":   req.TaskId,
	})
	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
		trace.StringAttribute("taskID", req.TaskId),
		trace.StringAttribute("assignmentID", req.TaskId))

	leaseAcquisitionStart := time.Now()
	if err := vpcService.concurrentRequests.Acquire(ctx, 1); err != nil {
		err = fmt.Errorf("Could not acquire concurrent require semaphore: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer vpcService.concurrentRequests.Release(1)
	span.AddAttributes(trace.Int64Attribute("leaseAcquisitionTime", time.Since(leaseAcquisitionStart).Nanoseconds()))

	if req.Idempotent {
		val, err := vpcService.fetchIdempotentAssignment(ctx, req.TaskId, true)
		if err != nil {
			err = errors.Wrap(err, "Cannot fetch idempotent assignment")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		if val != nil {
			return val, nil
		}
	}

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
			if !sets.NewString(req.Subnets...).Has(alloc.SubnetID) {
				err = fmt.Errorf("Allocation in subnet %s, but request asked for in subnet ids %q", alloc.SubnetID, req.Subnets)
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		}
		req.Subnets = []string{alloc.SubnetID}
	}

	accountID := aws.StringValue(trunkENI.OwnerId)
	if req.AccountID != "" {
		accountID = req.AccountID
	}

	subnet, err := vpcService.getLeastUsedSubnet(ctx, aws.StringValue(instance.Placement.AvailabilityZone), accountID, req.Subnets)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	span.AddAttributes(trace.StringAttribute("subnet", subnet.SubnetID))
	logger.G(ctx).WithField("subnet", subnet).Debug("Chose subnet to schedule into")

	maxIPAddresses, err := vpc.GetMaxIPAddresses(aws.StringValue(instance.InstanceType))
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	// Because there might be a prefix on the interface.
	maxIPAddresses--

	maxBranchENIs, err := vpc.GetMaxBranchENIs(aws.StringValue(instance.InstanceType))
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	maxBandwidth := req.Bandwidth
	if req.Burst {
		maxBandwidth, err = vpc.GetMaxNetworkbps(aws.StringValue(instance.InstanceType))
		if err != nil {
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	_, transitionRequested := req.Ipv4.(*vpcapi.AssignIPRequestV3_TransitionRequested)

	ass, err := vpcService.generateAssignmentID(ctx, getENIRequest{
		region:           subnet.Region,
		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		trunkENISession:  instanceSession,
		branchENIAccount: subnet.AccountID,
		assignmentID:     req.TaskId,
		subnet:           subnet,
		securityGroups:   req.SecurityGroupIds,
		maxBranchENIs:    maxBranchENIs,
		maxIPAddresses:   maxIPAddresses,

		bandwidth: req.Bandwidth,
		ceil:      maxBandwidth,
		jumbo:     req.Jumbo,

		transitionAssignmentRequested: transitionRequested,
	})
	if err != nil {
		return nil, err
	}

	resp, err := vpcService.assignIPsToENI(ctx, req, ass, maxIPAddresses)
	if err != nil {
		err = fmt.Errorf("Could not assign IPs to ENI: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	resp.TrunkNetworkInterface = instanceNetworkInterface(*instance, *trunkENI)
	return resp, nil
}

func (vpcService *vpcService) getRoutes(ctx context.Context, subnetID string) []*vpcapi.AssignIPResponseV3_Route {
	val, ok := vpcService.routesCache.Load(subnetID)
	if ok {
		return val.([]*vpcapi.AssignIPResponseV3_Route)
	}
	logger.G(ctx).WithField("subnet", subnetID).Warning("Could not load routes")
	return []*vpcapi.AssignIPResponseV3_Route{
		{

			Destination: "0.0.0.0/0",
			Mtu:         9000,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv4,
		},
		{
			Destination: "::/0",
			Mtu:         9000,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv6,
		},
	}
}

func lockAssignment(ctx context.Context, tx *sql.Tx, id int) (*data.Assignment, error) {
	ctx, span := trace.StartSpan(ctx, "lockAssignment")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("assignmentID", int64(id)))

	assignment, err := db.GetAndLockAssignmentByID(ctx, tx, id)
	if err != nil {
		err = errors.Wrap(err, "Cannot get and lock assignment in DB")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	return assignment, nil
}

func (vpcService *vpcService) assignIPsToENI(ctx context.Context, req *vpcapi.AssignIPRequestV3, ass *assignment, maxIPAddresses int) (*vpcapi.AssignIPResponseV3, error) { // nolint: gocyclo
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "assignIPsToENI")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("eni", ass.branch.id),
		trace.Int64Attribute("idx", int64(ass.branch.idx)),
		trace.StringAttribute("trunk", ass.trunk),
		trace.StringAttribute("branch", ass.branch.id),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"eni":    ass.branch.id,
		"trunk":  ass.trunk,
		"branch": ass.branch.id,
	})
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Cannot start transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = lockAssignment(ctx, tx, ass.assignmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot lock assignment")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	var transitionAss *data.Assignment
	if ass.transitionAssignmentID > 0 {
		transitionAss, err = lockAssignment(ctx, tx, ass.transitionAssignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot lock transition assignment")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	// This locks the branch ENI making this whole process "exclusive"
	dbSecurityGroups, err := db.GetSecurityGroupsAndLockBranchENI(ctx, tx, ass.branch.id)
	if err != nil {
		err = errors.Wrap(err, "Cannot get SGs assigned to branch ENI in DB")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if !sets.NewString(dbSecurityGroups...).Equal(sets.NewString(req.SecurityGroupIds...)) {
		err = fmt.Errorf("Database has security groups %s, when expected %s", dbSecurityGroups, req.SecurityGroupIds)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	iface, err := ass.branchENISession.GetNetworkInterfaceByID(ctx, ass.branch.id, 100*time.Millisecond)
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
		logger.G(ctx).WithField("traceid", span.SpanContext().TraceID.String()).Warnf("Branch ENI has security groups %s, when expected %s", hasSecurityGroupSet.List(), req.SecurityGroupIds)
	}

	/*
		TODO: Consider adding this back
		if s := aws.StringValue(iface.Status); s != "in-use" {
			err = fmt.Errorf("Branch ENI not in expected status, instead: %q", s)
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	*/

	resp := vpcapi.AssignIPResponseV3{
		Bandwidth: &vpcapi.AssignIPResponseV3_Bandwidth{
			Bandwidth: ass.bandwidth,
			Burst:     ass.ceil,
		},
	}
	switch ipv4req := (req.Ipv4).(type) {
	case *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation:
		resp.Ipv4Address, err = assignSpecificIPv4AddressV3(ctx, tx, iface, maxIPAddresses, ipv4req, ass)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	case *vpcapi.AssignIPRequestV3_Ipv4AddressRequested:
		resp.Ipv4Address, err = assignArbitraryIPv4AddressV3(ctx, tx, iface, maxIPAddresses, ass.subnet.Cidr, ass.branch, ass.branchENISession)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	case *vpcapi.AssignIPRequestV3_TransitionRequested:
		resp.TransitionAssignment = &vpcapi.AssignIPResponseV3_TransitionAssignment{
			AssignmentId: transitionAss.AssignmentID,
			Routes:       vpcService.getRoutes(ctx, ass.subnet.SubnetID),
		}
		if transitionAss.IPv4Addr.Valid {
			_, ipnet, err := net.ParseCIDR(transitionAss.CIDR)
			if err != nil {
				err = fmt.Errorf("Cannot parse cidr %q: %w", transitionAss.CIDR, err)
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
			prefixlength, _ := ipnet.Mask.Size()

			resp.TransitionAssignment.Ipv4Address = &vpcapi.UsableAddress{
				Address: &vpcapi.Address{
					Address: transitionAss.IPv4Addr.String,
				},
				PrefixLength: uint32(prefixlength),
			}
		} else {
			resp.TransitionAssignment.Ipv4Address, err = assignArbitraryIPv4AddressV3(ctx, tx, iface, maxIPAddresses, transitionAss.CIDR, ass.branch, ass.branchENISession)
			if err != nil {
				err = fmt.Errorf("Could not assign IPv4 address for transition assignment: %w", err)
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
			_, err = tx.ExecContext(ctx, "UPDATE assignments SET ipv4addr = $1, completed = true WHERE id = $2", resp.TransitionAssignment.Ipv4Address.Address.Address, ass.transitionAssignmentID)
			if err != nil {
				err = errors.Wrap(err, "Cannot update transition assignment with v4 addr")
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
		}
	}
	if resp.Ipv4Address != nil {
		span.AddAttributes(trace.StringAttribute("ipv4", net.ParseIP(resp.Ipv4Address.Address.Address).String()))
		_, err = tx.ExecContext(ctx, "UPDATE assignments SET ipv4addr = $1 WHERE id = $2", resp.Ipv4Address.Address.Address, ass.assignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot update assignment with v4 addr")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		// TODO(The user will get no public IP if they don't assign an IPv4 IP
		switch eip := (req.ElasticAddress).(type) {
		case *vpcapi.AssignIPRequestV3_ElasticAdddresses:
			resp.ElasticAddress, err = assignElasticAddressesBasedOnIDs(ctx, tx, ass.branchENISession, iface, resp.Ipv4Address, eip.ElasticAdddresses, req.TaskId)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		case *vpcapi.AssignIPRequestV3_GroupName:
			resp.ElasticAddress, err = assignElasticAddressesBasedOnGroupName(ctx, tx, ass.branchENISession, iface, resp.Ipv4Address, eip.GroupName, req.TaskId)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
		case *vpcapi.AssignIPRequestV3_Empty:
		}
	}

	switch (req.Ipv6).(type) {
	case *vpcapi.AssignIPRequestV3_Ipv6AddressRequested:
		// TODO: Remove
		resp.Ipv6Address, err = assignArbitraryIPv6AddressV3(ctx, tx, iface, maxIPAddresses, ass)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	case *vpcapi.AssignIPRequestV3_NoIPv6AddressRequested:
	}

	if resp.Ipv6Address != nil {
		span.AddAttributes(trace.StringAttribute("ipv6", net.ParseIP(resp.Ipv6Address.Address.Address).String()))
		_, err = tx.ExecContext(ctx, "UPDATE assignments SET ipv6addr = $1 WHERE id = $2", resp.Ipv6Address.Address.Address, ass.assignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot update assignment with v6 addr")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET last_assigned_to = now(), last_used = now() WHERE branch_eni = $1", aws.StringValue(iface.NetworkInterfaceId))
	if err != nil {
		err = errors.Wrap(err, "Cannot update last_assigned_to")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	resp.BranchNetworkInterface = &vpcapi.NetworkInterface{
		SubnetId:           ass.subnet.SubnetID,
		AvailabilityZone:   ass.branch.az,
		MacAddress:         aws.StringValue(iface.MacAddress),
		NetworkInterfaceId: ass.branch.id,
		OwnerAccountId:     ass.branch.accountID,
		VpcId:              ass.subnet.VpcID,
	}
	resp.VlanId = uint32(ass.branch.idx)

	row := tx.QueryRowContext(ctx, `
UPDATE htb_classid
SET assignment_id = $1
WHERE id =
    (SELECT id
     FROM htb_classid
     WHERE trunk_eni =
         (SELECT id
          FROM trunk_enis
          WHERE trunk_eni = $2)
       AND assignment_id IS NULL
     ORDER BY RANDOM()
     LIMIT 1) RETURNING class_id`, ass.assignmentID, ass.trunk)
	err = row.Scan(&resp.ClassId)
	if err != nil {
		err = errors.Wrap(err, "Unable to update / set class id for allocation")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "UPDATE assignments SET completed = true WHERE id = $1", ass.assignmentID)
	if err != nil {
		err = errors.Wrap(err, "Cannot update completed")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	resp.Routes = vpcService.getRoutes(ctx, ass.subnet.SubnetID)
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

	elasticAddress, err := db.GetAvailableElasticAddressByAllocationIDsAndLock(
		ctx, tx, aws.StringValue(branchENI.OwnerId), borderGroup, addresses)
	if err != nil {
		if err == sql.ErrNoRows {
			err = fmt.Errorf("no EIP in list %s free", addresses)
		} else {
			err = errors.Wrap(err, "Cannot query for free elastic IPs")
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	row := tx.QueryRowContext(ctx, "INSERT INTO elastic_ip_attachments(elastic_ip_allocation_id, assignment_id) VALUES ($1, $2) RETURNING id",
		elasticAddress.AllocationId, assignmentID)
	var id int
	err = row.Scan(&id)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert into elastic_ip_attachments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	associateAddressOutput, err := session.AssociateAddress(ctx, ec2.AssociateAddressInput{
		AllocationId:       aws.String(elasticAddress.AllocationId),
		AllowReassociation: aws.Bool(true),
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddress:   aws.String(ipv4Address.Address.Address),
	})
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}
	elasticAddress.AssociationdId = aws.StringValue(associateAddressOutput.AssociationId)

	_, err = tx.ExecContext(ctx, "UPDATE elastic_ip_attachments SET association_id = $1 WHERE id = $2", aws.StringValue(associateAddressOutput.AssociationId), id)
	if err != nil {
		err = errors.Wrap(err, "Unable to update elastic_ip_attachments table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return elasticAddress, nil
}

func assignElasticAddressesBasedOnGroupName(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, branchENI *ec2.NetworkInterface, ipv4Address *vpcapi.UsableAddress, groupName, assignmentID string) (*vpcapi.ElasticAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignElasticAddressesBasedOnGroupName")
	defer span.End()

	borderGroup, err := getBorderGroupForENI(ctx, tx, branchENI)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	elasticAddress, err := db.GetAvailableElasticAddressByGroupAndLock(ctx, tx, aws.StringValue(branchENI.OwnerId), borderGroup, groupName)
	if err != nil {
		if err == sql.ErrNoRows {
			err = fmt.Errorf("no EIP in group %s free in network border group %s", groupName, borderGroup)
		} else {
			err = errors.Wrap(err, "Cannot get free elastic IPs from DB")
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row := tx.QueryRowContext(ctx, "INSERT INTO elastic_ip_attachments(elastic_ip_allocation_id, assignment_id) VALUES ($1, $2) RETURNING id",
		elasticAddress.AllocationId, assignmentID)
	var id int
	err = row.Scan(&id)
	if err != nil {
		err = errors.Wrap(err, "Cannot insert into elastic_ip_attachments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	associateAddressOutput, err := session.AssociateAddress(ctx, ec2.AssociateAddressInput{
		AllocationId:       aws.String(elasticAddress.AllocationId),
		AllowReassociation: aws.Bool(true),
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddress:   aws.String(ipv4Address.Address.Address),
	})
	if err != nil {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}
	elasticAddress.AssociationdId = aws.StringValue(associateAddressOutput.AssociationId)

	_, err = tx.ExecContext(ctx, "UPDATE elastic_ip_attachments SET association_id = $1 WHERE id = $2", aws.StringValue(associateAddressOutput.AssociationId), id)
	if err != nil {
		err = errors.Wrap(err, "Unable to update elastic_ip_attachments table")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return elasticAddress, nil
}

func getBorderGroupForENI(ctx context.Context, tx *sql.Tx, eni *ec2.NetworkInterface) (string, error) {
	ctx, span := trace.StartSpan(ctx, "getBorderGroupForENI")
	defer span.End()

	az := aws.StringValue(eni.AvailabilityZone)
	accountID := aws.StringValue(eni.OwnerId)
	borderGroup, err := db.GetBorderGroupByAzAndAccount(ctx, tx, az, accountID)
	if err != nil {
		err = errors.Wrapf(err, "Cannot get border group for AZ %s in account %s", az, accountID)
		span.SetStatus(traceStatusFromError(err))
		return "", err
	}
	return borderGroup, nil
}

// // ctx, tx, iface, maxIPAddresses, ass
func assignArbitraryIPv6AddressV3(ctx context.Context, tx *sql.Tx, branchENI *ec2.NetworkInterface, maxIPAddresses int, ass *assignment) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignArbitraryIPv6AddressV3")
	defer span.End()

	row := tx.QueryRowContext(ctx, "UPDATE subnet_usable_prefix SET last_assigned = last_assigned + 1 WHERE branch_eni_id = $1 RETURNING last_assigned, prefix", ass.branch.intid)
	var lastAssigned int64
	var prefix string
	err := row.Scan(&lastAssigned, &prefix)
	if err != nil {
		err = fmt.Errorf("Cannot query / scan row from subnet_usable_prefix: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	_, net, err := net.ParseCIDR(prefix)
	if err != nil {
		err = fmt.Errorf("Cannot parse prefix %q: %w", prefix, err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	prefixInt := cidr.IPv6tod(net.IP)
	newIPInt := prefixInt.Add(prefixInt, big.NewInt(lastAssigned))
	newIP := cidr.DtoIPv6(newIPInt)

	return &vpcapi.UsableAddress{
		Address: &vpcapi.Address{
			Address: newIP.String(),
		},
		PrefixLength: uint32(128),
	}, nil
}

func assignArbitraryIPv4AddressV3(ctx context.Context, tx *sql.Tx, branchENI *ec2.NetworkInterface, maxIPAddresses int, cidr string, branch branchENI, branchENISession *ec2wrapper.EC2Session) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignArbitraryIPv4Address")
	defer span.End()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse cidr %s", cidr)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	prefixlength, _ := ipnet.Mask.Size()

	usedIPAddresses, err := db.GetUsedIPv4AddressesByENIAssociation(ctx, tx, branch.associationID)
	if err != nil {
		err = errors.Wrap(err, "Cannot get ipv4addrs already assigned to interface from DB")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
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
		staticIPAddresses, err := db.GetStaticIPv4Addresses(ctx, tx, unusedIPAddresses.List(), aws.StringValue(branchENI.SubnetId))
		if err != nil {
			err = errors.Wrap(err, "Cannot fetch statically assigned IP addresses from DB")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		for _, staticIPAddress := range staticIPAddresses {
			unusedIPAddresses.Delete(staticIPAddress)
		}
	}

	if l := unusedIPAddresses.Len(); l > 0 {
		unusedIPv4AddressesList := unusedIPAddresses.List()

		ipAddress, err := db.GetOldestAvailableIPv4(ctx, tx, unusedIPv4AddressesList, aws.StringValue(branchENI.VpcId))
		if err == sql.ErrNoRows {
			// Effectively choose a random one.
			ipAddress = unusedIPv4AddressesList[rand.Intn(l)] // nolint: gosec
		} else if err != nil {
			err = errors.Wrap(err, "Could not fetch utilized IPv4 addresses from the database")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		return &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: ipAddress,
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

	assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             branchENI.NetworkInterfaceId,
		SecondaryPrivateIpAddressCount: aws.Int64(int64(ipsToAssign)),
	}

	output, err := branchENISession.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput)
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

	staticIPAddresses, err := db.GetStaticIPv4Addresses(ctx, tx, newPrivateAddresses, aws.StringValue(branchENI.SubnetId))
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch statically assigned IP addresses from DB")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	for _, staticIPAddress := range staticIPAddresses {
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

func (vpcService *vpcService) unassignStaticAddress(ctx context.Context, taskID string) (bool, error) {
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

	statciIPAddress, err := db.GetAssignedStaticIPAddressByTaskID(ctx, tx, taskID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot query static addresses assignment from DB")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	region := azToRegionRegexp.FindString(statciIPAddress.AZ)
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: statciIPAddress.AccountID, Region: region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	_, err = session.AssignPrivateIPAddresses(ctx, ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(statciIPAddress.BranchENI),
		PrivateIpAddresses: aws.StringSlice([]string{statciIPAddress.IP}),
		AllowReassignment:  aws.Bool(true),
	})
	if err != nil {
		return false, ec2wrapper.HandleEC2Error(err, span)
	}

	// This will automagically cascade and delete the static attachment as well
	_, err = tx.ExecContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1", taskID)
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

func (vpcService *vpcService) unassignElasticAddress(ctx context.Context, taskID string) error {
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

	elasticIPAttachment, err := db.GetElasticIPAttachmentByTaskID(ctx, tx, taskID)
	if err == sql.ErrNoRows {
		return nil
	}

	if err != nil {
		err = errors.Wrap(err, "Could not get elastic IP associations from DB")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(
		ctx, ec2wrapper.Key{AccountID: elasticIPAttachment.AccountID, Region: elasticIPAttachment.Region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	_, err = session.DisassociateAddress(ctx, ec2.DisassociateAddressInput{
		AssociationId: aws.String(elasticIPAttachment.AssociationID),
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
	_, err = tx.ExecContext(ctx, "DELETE FROM elastic_ip_attachments WHERE id = $1", elasticIPAttachment.ID)
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

func (vpcService *vpcService) UnassignIPV3(ctx context.Context, req *vpcapi.UnassignIPRequestV3) (*vpcapi.UnassignIPResponseV3, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "UnassignIPV3")
	defer span.End()

	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	span.AddAttributes(trace.StringAttribute("assignmentID", req.TaskId))
	resp := vpcapi.UnassignIPResponseV3{}

	if err := vpcService.concurrentRequests.Acquire(ctx, 1); err != nil {
		err = fmt.Errorf("Could not acquire concurrent require semaphore: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer vpcService.concurrentRequests.Release(1)

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
	if err == sql.ErrNoRows {
		err = status.Errorf(codes.NotFound, "Could not find assignment ID %q in the database", req.TaskId)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not delete assignment from database").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT vpc_id, branch_enis.branch_eni FROM branch_enis JOIN branch_eni_attachments ON branch_eni_attachments.branch_eni = branch_enis.branch_eni WHERE branch_eni_attachments.association_id = $1", association)
	var vpcID, branchENIID string
	err = row.Scan(&vpcID, &branchENIID)
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not get VPC ID / Branch ENI ID from database").Error())
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

	_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET last_used = now() WHERE branch_eni = $1", branchENIID)
	if err != nil {
		err = fmt.Errorf("Could not update last_used on branch ENI: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
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

	return &resp, nil
}

func assignSpecificIPv4AddressV3(ctx context.Context, tx *sql.Tx, branchENI *ec2.NetworkInterface, maxIPAddresses int, alloc *vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation, ass *assignment) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignSpecificIPv4AddressV3")

	_, ipnet, err := net.ParseCIDR(ass.subnet.Cidr)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse cidr %s", ass.subnet.Cidr)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	prefixlength, _ := ipnet.Mask.Size()

	id := alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid
	staticAllocation, err := db.GetStaticAllocationByIDAndLock(ctx, tx, id)
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

	if staticAllocation.SubnetID != aws.StringValue(branchENI.SubnetId) {
		err = fmt.Errorf("Branch ENI in subnet %s, but IP allocation in subnet %s", aws.StringValue(branchENI.SubnetId), staticAllocation.SubnetID)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO ip_address_attachments(ip_address_uuid, assignment_id) VALUES ($1, $2)", id, ass.assignmentName)
	if err != nil {
		err = errors.Wrap(err, "Could not insert ip address attachment into database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddresses: aws.StringSlice([]string{staticAllocation.IP}),
		AllowReassignment:  aws.Bool(true),
	}

	// There's one error condition here which is kind of nasty and unaddressed (at least for now)
	// if there have been 50 users of the interface, and we come along, we'll blow out the max ip addresses
	// for the interface.
	//
	// A todo is to clean up / GC the interface prior to doing this assignment.
	output, err := ass.branchENISession.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput)
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
