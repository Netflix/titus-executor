package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/m7shapan/cidr"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	invalidAssociationIDNotFound = "InvalidAssociationID.NotFound"
	assignTimeout                = 5 * time.Minute

	// The P99 for get subnet is 3 seconds
	getSubnetTimeout = 10 * time.Second
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
	id        int
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
	return fmt.Sprintf("Subnet{id=%d vpc=%s, az=%s, subnet=%s, account=%s}", s.id, s.vpcID, s.az, s.subnetID, s.accountID)
}

type branchENI struct {
	intid         int64
	id            string
	az            string
	associationID string
	accountID     string
	idx           int
}

func subnetCacheKey(az, accountID string, subnetIDs []string) string {
	sort.Strings(subnetIDs)
	return fmt.Sprintf("az:%s accountID:%s subnetIDs:%s", az, accountID, strings.Join(subnetIDs, ","))
}

func (vpcService *vpcService) getSubnetUncached(ctx context.Context, az, accountID string, subnetIDs []string) (*subnet, error) {
	ctx, span := trace.StartSpan(ctx, "getSubnetUncached")
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
			err = newNotFoundError(fmt.Errorf("No subnet found matching IDs %s in az %s", subnetIDs, az))
		} else {
			err = newNotFoundError(fmt.Errorf("No subnet found in account %s in az %s", accountID, az))
		}
		tracehelpers.SetStatus(err, span)
		// explicitly not returning stale subnet here
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot fetch subnet ID from database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &ret, nil
}

func (vpcService *vpcService) getSubnet(ctx context.Context, az, accountID string, subnetIDs []string) (*subnet, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "getSubnet")
	defer span.End()

	// NOTE[jigish] caching using the full set of subnetIDs will cause the same subnet to be returned for all hits
	cacheKey := subnetCacheKey(az, accountID, subnetIDs)

	item := vpcService.getSubnetCache.Get(cacheKey)
	if item != nil {
		span.AddAttributes(trace.BoolAttribute("cached", true))
		val := item.Value().(*subnet)
		if !item.Expired() {
			return val, nil
		}

		span.AddAttributes(trace.BoolAttribute("expired", true))
		span.AddAttributes(trace.StringAttribute("expires", item.Expires().String()))

		span.AddAttributes(trace.BoolAttribute("stale", true))
	}

	spanContext := span.SpanContext()
	resultChan := vpcService.getSubnetLock.DoChan(cacheKey, func() (interface{}, error) {
		// There could be a race here between the time we checked above and this singleflight started
		// so check again
		//
		// Also, go scoping makes this confusing, so keep this name different than above
		item2 := vpcService.getSubnetCache.Get(cacheKey)
		if item2 != nil && !item2.Expired() {
			span.AddAttributes(trace.BoolAttribute("cached", true))
			return item2.Value().(*subnet), nil
		}

		// The lifetime of this singleflight should be independent of that of the connection / request
		ctx2, cancel2 := context.WithTimeout(context.Background(), getSubnetTimeout)
		defer cancel2()
		ctx2, span2 := trace.StartSpanWithRemoteParent(ctx2, "getSubnetSingleflight", spanContext)
		defer span2.End()
		subnet, err := vpcService.getSubnetUncached(ctx2, az, accountID, subnetIDs)
		if err != nil {
			tracehelpers.SetStatus(err, span2)
			return nil, err
		}
		vpcService.getSubnetCache.Set(cacheKey, subnet, vpcService.subnetCacheExpirationTime)
		return subnet, nil
	})

	select {
	case result := <-resultChan:
		span.AddAttributes(trace.BoolAttribute("shared", result.Shared))
		if result.Err == nil {
			return result.Val.(*subnet), nil
		}
		if item != nil {
			span.AddAttributes(trace.BoolAttribute("fallback", true))
			return item.Value().(*subnet), nil
		}
		tracehelpers.SetStatus(result.Err, span)
		return nil, result.Err
	case <-ctx.Done():
		tracehelpers.SetStatus(ctx.Err(), span)
		return nil, ctx.Err()
	}
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

func (vpcService *vpcService) fetchIdempotentAssignment(ctx context.Context, assignmentID string, deleteUnfinishedAssignment bool) (*vpcapi.AssignIPResponseV3, error) {
	ctx, span := trace.StartSpan(ctx, "fetchIdempotentAssignment")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("assignmentID", assignmentID),
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

	row := tx.QueryRowContext(ctx, `
SELECT assignments.id,
       bea.branch_eni,
       bea.trunk_eni,
       bea.idx,
       assignments.branch_eni_association,
       ipv4addr,
       ipv6addr,
       completed,
       jumbo,
       bandwidth,
       ceil,
       be.subnet_id
FROM assignments
JOIN branch_eni_attachments bea ON assignments.branch_eni_association = bea.association_id
JOIN branch_enis be on bea.branch_eni = be.branch_eni
WHERE assignment_id = $1
  FOR NO KEY
  UPDATE OF assignments`, assignmentID)
	var branchENI, trunkENI, associationID string
	var ipv4addr, ipv6addr, subnetID sql.NullString
	var idx, assignmentRowID int
	var completed, jumbo bool
	var bandwidth, ceil uint64
	err = row.Scan(&assignmentRowID, &branchENI, &trunkENI, &idx, &associationID, &ipv4addr, &ipv6addr, &completed,
		&jumbo, &bandwidth, &ceil, &subnetID)
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
			_, err = tx.ExecContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1", assignmentID)
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
		VlanId: uint32(idx),
		Bandwidth: &vpcapi.AssignIPResponseV3_Bandwidth{
			Bandwidth: bandwidth,
			Burst:     ceil,
		},
	}

	resp.Routes = vpcService.getRoutes(ctx, subnetID.String)

	row = tx.QueryRowContext(ctx, "SELECT subnet_id, az, mac, branch_eni, account_id, vpc_id FROM branch_enis WHERE branch_eni = $1", branchENI)
	err = row.Scan(&resp.BranchNetworkInterface.SubnetId,
		&resp.BranchNetworkInterface.AvailabilityZone,
		&resp.BranchNetworkInterface.MacAddress,
		&resp.BranchNetworkInterface.NetworkInterfaceId,
		&resp.BranchNetworkInterface.OwnerAccountId,
		&resp.BranchNetworkInterface.VpcId)
	if err != nil {
		err = errors.Wrap(err, "Cannot select branch_eni")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT subnet_id, az, mac, trunk_eni, account_id, vpc_id FROM trunk_enis WHERE trunk_eni = $1", trunkENI)
	err = row.Scan(&resp.TrunkNetworkInterface.SubnetId,
		&resp.TrunkNetworkInterface.AvailabilityZone,
		&resp.TrunkNetworkInterface.MacAddress,
		&resp.TrunkNetworkInterface.NetworkInterfaceId,
		&resp.TrunkNetworkInterface.OwnerAccountId,
		&resp.TrunkNetworkInterface.VpcId)
	if err != nil {
		err = errors.Wrap(err, "Cannot select trunk_eni")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	if ipv4addr.Valid {
		var subnetCIDR string
		row = tx.QueryRowContext(ctx, "SELECT cidr FROM subnets WHERE subnet_id = $1", resp.BranchNetworkInterface.SubnetId)
		err = row.Scan(&subnetCIDR)
		if err != nil {
			err = fmt.Errorf("Could not scan subnet CIDR %q: %w", resp.BranchNetworkInterface.SubnetId, err)
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		_, ipnet, err := net.ParseCIDR(subnetCIDR)
		if err != nil {
			err = fmt.Errorf("Could not parse subnet CIDR %q: %w", subnetCIDR, err)
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		ones, _ := ipnet.Mask.Size()
		resp.Ipv4Address = &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: ipv4addr.String,
			},
			PrefixLength: uint32(ones),
		}
	}

	if ipv6addr.Valid {
		resp.Ipv6Address = &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: ipv6addr.String,
			},
			PrefixLength: 128,
		}
	}

	row = tx.QueryRowContext(ctx, `
SELECT elastic_ip_attachments.elastic_ip_allocation_id,
       association_id,
       public_ip
FROM elastic_ip_attachments
JOIN elastic_ips ON elastic_ip_attachments.elastic_ip_allocation_id = elastic_ips.allocation_id
WHERE assignment_id = $1`, assignmentID)
	var elasticIPAllocationID, elasticIPAssociationID, publicIP string
	err = row.Scan(&elasticIPAllocationID, &elasticIPAssociationID, &publicIP)
	if err == nil {
		resp.ElasticAddress = &vpcapi.ElasticAddress{
			Ip:             publicIP,
			AllocationId:   elasticIPAllocationID,
			AssociationdId: elasticIPAssociationID,
		}
	} else if err != sql.ErrNoRows {
		err = errors.Wrap(err, "Could not select from elastic IP allocations table")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	row = tx.QueryRowContext(ctx, "SELECT class_id FROM htb_classid WHERE assignment_id = $1", assignmentRowID)
	err = row.Scan(&resp.ClassId)
	if err != nil {
		err = errors.Wrapf(err, "Cannot get HTB class ID for assignment %d", assignmentRowID)
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

	if req.InstanceIdentity == nil || req.InstanceIdentity.InstanceID == "" {
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
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	span.AddAttributes(trace.StringAttribute("subnet", subnet.subnetID))
	logger.G(ctx).WithField("subnet", subnet).Debug("Chose subnet to schedule into")

	maxIPAddresses, err := vpc.GetMaxIPAddresses(aws.StringValue(instance.InstanceType))
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

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

	ipv6NotRequested := false
	if _, ok := req.Ipv6.(*vpcapi.AssignIPRequestV3_Ipv6AddressRequested); !ok {
		ipv6NotRequested = true
	}
	ass, err := vpcService.generateAssignmentID(ctx, getENIRequest{
		region:           subnet.region,
		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		trunkENISession:  instanceSession,
		branchENIAccount: subnet.accountID,
		assignmentID:     req.TaskId,
		subnet:           subnet,
		securityGroups:   req.SecurityGroupIds,
		maxBranchENIs:    maxBranchENIs,
		maxIPAddresses:   maxIPAddresses,

		bandwidth: req.Bandwidth,
		ceil:      maxBandwidth,
		jumbo:     req.Jumbo,

		transitionAssignmentRequested: transitionRequested,
		ipv6NotRequested:              ipv6NotRequested,
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

type sqlAssignment struct {
	assignmentID string
	ipv4addr     sql.NullString
	ipv6addr     sql.NullString
	cidr         string
}

func lockAssignment(ctx context.Context, tx *sql.Tx, assignmentID int) (*sqlAssignment, error) {
	ctx, span := trace.StartSpan(ctx, "lockAssignment")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("assignmentID", int64(assignmentID)))

	var ass sqlAssignment
	row := tx.QueryRowContext(ctx, `
SELECT assignment_id, cidr, ipv4addr, ipv6addr
FROM assignments 
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
JOIN subnets on branch_enis.subnet_id = subnets.subnet_id
WHERE assignments.id = $1 FOR NO KEY UPDATE OF assignments
`, assignmentID)
	err := row.Scan(&ass.assignmentID, &ass.cidr, &ass.ipv4addr, &ass.ipv6addr)
	if err != nil {
		err = errors.Wrap(err, "Cannot select assignment for no key update")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &ass, nil
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

	var transitionAss *sqlAssignment
	if ass.transitionAssignmentID > 0 {
		transitionAss, err = lockAssignment(ctx, tx, ass.transitionAssignmentID)
		if err != nil {
			err = errors.Wrap(err, "Cannot lock transition assignment")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
	}

	// This locks the branch ENI making this whole process "exclusive"
	row := tx.QueryRowContext(ctx, "SELECT security_groups FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", ass.branch.id)
	var dbSecurityGroups []string
	err = row.Scan(pq.Array(&dbSecurityGroups))
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
		logger.G(ctx).WithField("spanid", span.SpanContext().SpanID.String()).Warnf("Branch ENI has security groups %s, when expected %s", hasSecurityGroupSet.List(), req.SecurityGroupIds)
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
		resp.Ipv4Address, err = assignArbitraryIPv4AddressV3(ctx, tx, iface, maxIPAddresses, ass.subnet.cidr, ass.branch, ass.branchENISession)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	case *vpcapi.AssignIPRequestV3_TransitionRequested:
		resp.TransitionAssignment = &vpcapi.AssignIPResponseV3_TransitionAssignment{
			AssignmentId: transitionAss.assignmentID,
			Routes:       vpcService.getRoutes(ctx, ass.subnet.subnetID),
		}
		if transitionAss.ipv4addr.Valid {
			_, ipnet, err := net.ParseCIDR(transitionAss.cidr)
			if err != nil {
				err = fmt.Errorf("Cannot parse cidr %q: %w", transitionAss.cidr, err)
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
			prefixlength, _ := ipnet.Mask.Size()

			resp.TransitionAssignment.Ipv4Address = &vpcapi.UsableAddress{
				Address: &vpcapi.Address{
					Address: transitionAss.ipv4addr.String,
				},
				PrefixLength: uint32(prefixlength),
			}
		} else {
			resp.TransitionAssignment.Ipv4Address, err = assignArbitraryIPv4AddressV3(ctx, tx, iface, maxIPAddresses, transitionAss.cidr, ass.branch, ass.branchENISession)
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
		SubnetId:           ass.subnet.subnetID,
		AvailabilityZone:   ass.branch.az,
		MacAddress:         aws.StringValue(iface.MacAddress),
		NetworkInterfaceId: ass.branch.id,
		OwnerAccountId:     ass.branch.accountID,
		VpcId:              ass.subnet.vpcID,
	}
	resp.VlanId = uint32(ass.branch.idx)

	row = tx.QueryRowContext(ctx, `
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

	resp.Routes = vpcService.getRoutes(ctx, ass.subnet.subnetID)
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

	associateAddressOutput, err := session.AssociateAddress(ctx, ec2.AssociateAddressInput{
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

	associateAddressOutput, err := session.AssociateAddress(ctx, ec2.AssociateAddressInput{
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

	usedIPAddresses := sets.NewString()
	rows, err := tx.QueryContext(ctx, "SELECT ipv4addr FROM assignments WHERE ipv4addr IS NOT NULL AND branch_eni_association = $1", branch.associationID)
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

	if l := unusedIPAddresses.Len(); l > 0 {
		unusedIPv4AddressesList := unusedIPAddresses.List()

		row := tx.QueryRowContext(ctx, "SELECT ip_address FROM ip_last_used_v3 WHERE ip_address = any($1::inet[]) AND vpc_id = $2  ORDER BY last_seen ASC LIMIT 1", pq.Array(unusedIPv4AddressesList), aws.StringValue(branchENI.VpcId))
		var ipAddress string
		err = row.Scan(&ipAddress)
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

	_, err = session.AssignPrivateIPAddresses(ctx, ec2.AssignPrivateIpAddressesInput{
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

	_, err = session.DisassociateAddress(ctx, ec2.DisassociateAddressInput{
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

	_, ipnet, err := net.ParseCIDR(ass.subnet.cidr)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse cidr %s", ass.subnet.cidr)
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

	_, err = tx.ExecContext(ctx, "INSERT INTO ip_address_attachments(ip_address_uuid, assignment_id) VALUES ($1, $2)", id, ass.assignmentName)
	if err != nil {
		err = errors.Wrap(err, "Could not insert ip address attachment into database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddresses: aws.StringSlice([]string{ip}),
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

func assignNextIPv6Address(ctx context.Context, tx *sql.Tx, subnetid string) (net.IP, error) {
	sequenceName := fmt.Sprintf("v6seq_%s", strings.ReplaceAll(subnetid, "-", "_"))
	_, err := tx.ExecContext(ctx, fmt.Sprintf("CREATE SEQUENCE IF NOT EXISTS %s MINVALUE 0 MAXVALUE 65534 CACHE 10 CYCLE", sequenceName))
	if err != nil {
		return nil, fmt.Errorf("Cannot create sequence %s: %w", sequenceName, err)
	}

	/*
			The address layout looks like:

		 ┌───────────────────────────┬──────────────┬───────────────────────────┬────────────────────┐
		 │ AWS Subnet CIDR (64-bits) │ 0s (16 bits) │ Time in Seconds (32-bits) │ Sequence (16-bits) │
		 └───────────────────────────┴──────────────┴───────────────────────────┴────────────────────┘

	*/

	row := tx.QueryRowContext(ctx, "SELECT nextval($1)", sequenceName)
	var lsb int64
	err = row.Scan(&lsb)
	if err != nil {
		return nil, fmt.Errorf("Cannot scan nextval from sequence %s: %w", sequenceName, err)
	}

	now := time.Now().Unix() // Should be in seconds
	lsb |= now << 12
	lsb &= (1 << 48) - 1

	row = tx.QueryRowContext(ctx, "SELECT cidr6 FROM subnets WHERE subnet_id = $1", subnetid)
	var subnetCIDR sql.NullString
	err = row.Scan(&subnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("Cannot scan cidr6 from subnet %s: %w", subnetid, err)
	}

	if !subnetCIDR.Valid {
		return nil, fmt.Errorf("Subnet %s does not have cidr6", subnetid)
	}

	_, net, err := net.ParseCIDR(subnetCIDR.String)
	if err != nil {
		err = fmt.Errorf("Cannot parse prefix %q: %w", subnetCIDR.String, err)
		return nil, err
	}

	prefixInt := cidr.IPv6tod(net.IP)
	newIPInt := prefixInt.Add(prefixInt, big.NewInt(lsb))
	newIP := cidr.DtoIPv6(newIPInt)
	return newIP, nil
}
