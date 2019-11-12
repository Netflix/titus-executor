package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

func isAssignIPRequestValid(req *vpcapi.AssignIPRequest) error {
	if req.NetworkInterfaceAttachment.DeviceIndex == 0 {
		return status.Error(codes.InvalidArgument, "Device index 0 not allowed")
	}

	return nil
}

func isAssignIPRequestValidForInstance(req *vpcapi.AssignIPRequest, instance *ec2.Instance) error {
	maxInterfaces, err := vpc.GetMaxInterfaces(*instance.InstanceType)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	if int(req.NetworkInterfaceAttachment.DeviceIndex) >= maxInterfaces {
		return status.Error(codes.InvalidArgument, "Interface is out of bounds")
	}

	return nil
}

func (vpcService *vpcService) AssignIP(ctx context.Context, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssignIP")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
		trace.BoolAttribute("ipv6AddressRequested", req.Ipv6AddressRequested),
		trace.StringAttribute("securityGroupIds", fmt.Sprint(req.SecurityGroupIds)),
		trace.StringAttribute("allowSecurityGroupChange", fmt.Sprint(req.AllowSecurityGroupChange)),
		trace.Int64Attribute("deviceIdx", int64(req.GetNetworkInterfaceAttachment().DeviceIndex)),
	)

	if err := isAssignIPRequestValid(req); err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: req.InstanceIdentity.Region, AccountID: req.InstanceIdentity.AccountID})
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	instance, ownerID, err := session.GetInstance(ctx, req.InstanceIdentity.InstanceID, ec2wrapper.UseCache)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = isAssignIPRequestValidForInstance(req, instance)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	maxIPAddresses, err := vpc.GetMaxIPAddresses(aws.StringValue(instance.InstanceType))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	instanceIface, err := ec2wrapper.GetInterfaceByIdxWithRetries(ctx, session, instance, req.NetworkInterfaceAttachment.DeviceIndex)
	if err != nil {
		if ec2wrapper.IsErrInterfaceByIdxNotFound(err) {
			err = status.Error(codes.NotFound, err.Error())
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	networkInterfaceID := aws.StringValue(instanceIface.NetworkInterfaceId)
	span.AddAttributes(trace.StringAttribute("eni", networkInterfaceID))
	ctx = logger.WithField(ctx, "eni", networkInterfaceID)

	iface, err := session.GetNetworkInterfaceByID(ctx, networkInterfaceID, 100*time.Millisecond)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	// Is the owner of the original session (the instance session) different than the one we need to use for the interface
	if interfaceOwnerID := aws.StringValue(iface.OwnerId); interfaceOwnerID != ownerID {
		logger.G(ctx).WithField("accountID", aws.StringValue(iface.OwnerId)).Debug("Setting up session from alternative account for assignment")
		az := aws.StringValue(instance.Placement.AvailabilityZone)
		region := ec2wrapper.RegionFromAZ(az)
		session, err = vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: region, AccountID: interfaceOwnerID})
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		iface, err = session.GetNetworkInterfaceByID(ctx, networkInterfaceID, time.Millisecond*100)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	subnet, err := session.GetSubnetByID(ctx, aws.StringValue(iface.SubnetId), ec2wrapper.UseCache)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	// TODO: Validate these
	wantedSecurityGroups := aws.StringSlice(req.GetSecurityGroupIds())
	// Assign default security groups
	if len(wantedSecurityGroups) == 0 {

		wantedSecurityGroups, err = session.GetDefaultSecurityGroups(ctx, aws.StringValue(instanceIface.VpcId))
		if err != nil {
			err = status.Error(codes.NotFound, errors.Wrap(err, "Could not fetch default security groups").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	wantedSecurityGroupsSet := set.NewSet()
	for idx := range wantedSecurityGroups {
		wantedSecurityGroupsSet.Add(*wantedSecurityGroups[idx])
	}
	hasSecurityGroupsSet := set.NewSet()
	for idx := range iface.Groups {
		hasSecurityGroupsSet.Add(*iface.Groups[idx].GroupId)
	}

	if !wantedSecurityGroupsSet.Equal(hasSecurityGroupsSet) {
		if !req.AllowSecurityGroupChange {
			span.AddAttributes(trace.StringAttribute("currentSecurityGroups", hasSecurityGroupsSet.String()))
			span.Annotate(nil, "Cannot change security groups")
			err = status.Error(codes.FailedPrecondition, "Security group change required, but not allowed")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		logger.G(ctx).WithField("currentSecurityGroups", hasSecurityGroupsSet.ToSlice()).WithField("newSecurityGroups", wantedSecurityGroupsSet.ToSlice()).Info("Changing security groups")
		err = session.ModifySecurityGroups(ctx, networkInterfaceID, wantedSecurityGroups)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	if len(req.SignedAddressAllocations) > 0 {
		logger.G(ctx).Debug("Performing static address allocation")
		return vpcService.assignAddressesFromAllocations(ctx, session, iface, subnet, req)
	}

	return vpcService.assignAddresses(ctx, session, iface, req, subnet, maxIPAddresses, true)
}

func (vpcService *vpcService) assignAddressesFromAllocations(ctx context.Context, session *ec2wrapper.EC2Session, ni *ec2.NetworkInterface, subnet *ec2.Subnet, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
	ctx, span := trace.StartSpan(ctx, "assignAddressesFromAllocations")
	defer span.End()

	_, ipnet, err := net.ParseCIDR(*subnet.CidrBlock)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot parse CIDR block")
	}
	prefixlength, _ := ipnet.Mask.Size()

	assignedIPv4addresses := set.NewSet()
	assignedIPv6addresses := set.NewSet()
	assignedIPv4addresses.Add(net.ParseIP(*ni.PrivateIpAddress).String())
	for idx := range ni.PrivateIpAddresses {
		pi := ni.PrivateIpAddresses[idx]
		assignedIPv4addresses.Add(net.ParseIP(*pi.PrivateIpAddress).String())
	}
	for idx := range ni.Ipv6Addresses {
		pi := ni.Ipv6Addresses[idx]
		assignedIPv6addresses.Add(net.ParseIP(*pi.Ipv6Address).String())
	}

	ipv6Addresses := []net.IP{}
	ipv6AddressesToAssign := []net.IP{}

	ipv4Addresses := []net.IP{}
	ipv4AddressesToAssign := []net.IP{}

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

	for _, assignment := range req.SignedAddressAllocations {
		var ipAddress, subnetID string
		row := tx.QueryRowContext(ctx, "SELECT ip_address, subnet_id FROM ip_addresses WHERE id = $1", assignment.AddressAllocation.Uuid)
		err = row.Scan(&ipAddress, &subnetID)
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not perform db query").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		if ip := net.ParseIP(ipAddress); ip.To4() == nil {
			if !assignedIPv6addresses.Contains(ip.String()) {
				ipv6AddressesToAssign = append(ipv6AddressesToAssign, ip)
			}
			ipv6Addresses = append(ipv6Addresses, ip)
		} else {
			if !assignedIPv4addresses.Contains(ip.String()) {
				ipv4AddressesToAssign = append(ipv6AddressesToAssign, ip)
			}
			ipv4Addresses = append(ipv4Addresses, ip)
		}
	}

	if len(ipv4AddressesToAssign) > 0 {
		logger.G(ctx).WithField("ipv4AddressesToAssign", ipv4AddressesToAssign).Debug("Assigning IPv4 Addresses")
		assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
			AllowReassignment:  aws.Bool(true),
			PrivateIpAddresses: make([]*string, len(ipv4AddressesToAssign)),
			NetworkInterfaceId: ni.NetworkInterfaceId,
		}
		for idx := range ipv4AddressesToAssign {
			assignPrivateIPAddressesInput.PrivateIpAddresses[idx] = aws.String(ipv4AddressesToAssign[idx].String())
		}
		logger.G(ctx).WithField("ipv4AddressesToAssign", ipv4AddressesToAssign).Debug("Assigning static IPv4 Addresses")
		if _, err := session.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput); err != nil {
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}
	}

	if len(ipv6AddressesToAssign) > 0 {
		logger.G(ctx).WithField("ipv6AddressesToAssign", ipv6AddressesToAssign).Debug("Assigning IPv6 Addresses")
		assignIpv6AddressesInput := ec2.AssignIpv6AddressesInput{
			Ipv6Addresses:      make([]*string, len(ipv6AddressesToAssign)),
			NetworkInterfaceId: ni.NetworkInterfaceId,
		}
		for idx := range ipv6AddressesToAssign {
			assignIpv6AddressesInput.Ipv6Addresses[idx] = aws.String(ipv6AddressesToAssign[idx].String())
		}
		logger.G(ctx).WithField("ipv6AddressesToAssign", ipv4AddressesToAssign).Debug("Assigning static IPv6 Addresses")
		if _, err := session.AssignIPv6Addresses(ctx, assignIpv6AddressesInput); err != nil {
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}
	}

	ni, err = session.GetNetworkInterfaceByID(ctx, aws.StringValue(ni.NetworkInterfaceId), time.Millisecond*100)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ret := &vpcapi.AssignIPResponse{
		CacheVersion:     nil,
		UsableAddresses:  make([]*vpcapi.UsableAddress, 0, len(req.SignedAddressAllocations)),
		NetworkInterface: networkInterface(*ni),
	}

	for idx := range ipv4Addresses {
		ret.UsableAddresses = append(ret.UsableAddresses, &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: ipv4Addresses[idx].String(),
			},
			// TODO fix
			PrefixLength: uint32(prefixlength),
		})
	}
	for idx := range ipv6Addresses {
		ret.UsableAddresses = append(ret.UsableAddresses, &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: ipv6Addresses[idx].String(),
			},
			PrefixLength: uint32(128),
		})
	}

	return ret, nil
}

func (vpcService *vpcService) assignAddresses(ctx context.Context, session *ec2wrapper.EC2Session, ni *ec2.NetworkInterface, req *vpcapi.AssignIPRequest, subnet *ec2.Subnet, maxIPAddresses int, allowAssignment bool) (*vpcapi.AssignIPResponse, error) {
	ctx, span := trace.StartSpan(ctx, "assignAddresses")
	defer span.End()
	entry := logger.G(ctx).WithField("allowAssignment", allowAssignment)
	response := &vpcapi.AssignIPResponse{}
	utilizedAddressIPv4Set := set.NewSet()
	utilizedAddressIPv6Set := set.NewSet()

	for _, addr := range req.UtilizedAddresses {
		canonicalAddress := net.ParseIP(addr.Address.Address)
		if canonicalAddress.To4() == nil {
			utilizedAddressIPv6Set.Add(canonicalAddress.String())
		} else {
			utilizedAddressIPv4Set.Add(canonicalAddress.String())
		}
	}

	if utilizedAddressIPv4Set.Cardinality() >= maxIPAddresses {
		return nil, status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses assigned, interface can only handle %d IPs", utilizedAddressIPv4Set.Cardinality(), maxIPAddresses)
	}
	if utilizedAddressIPv6Set.Cardinality() >= maxIPAddresses {
		return nil, status.Errorf(codes.FailedPrecondition, "%d IPv6 addresses assigned, interface can only handle %d IPs", utilizedAddressIPv6Set.Cardinality(), maxIPAddresses)
	}

	response.NetworkInterface = networkInterface(*ni)
	response.SecurityGroupIds = make([]string, len(ni.Groups))
	assignedIPv4addresses := set.NewSet()
	assignedIPv6addresses := set.NewSet()
	assignedIPv4addresses.Add(net.ParseIP(*ni.PrivateIpAddress).String())

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

	for idx := range ni.PrivateIpAddresses {
		pi := ni.PrivateIpAddresses[idx]
		assignedIPv4addresses.Add(net.ParseIP(*pi.PrivateIpAddress).String())
	}
	for idx := range ni.Ipv6Addresses {
		pi := ni.Ipv6Addresses[idx]
		assignedIPv6addresses.Add(net.ParseIP(*pi.Ipv6Address).String())
	}

	staticallyAllocatedAddressesSet := set.NewSet()
	assignedAddresses := []string{}
	for addr := range assignedIPv4addresses.Iter() {
		assignedAddresses = append(assignedAddresses, addr.(string))
	}
	for addr := range assignedIPv6addresses.Iter() {
		assignedAddresses = append(assignedAddresses, addr.(string))
	}
	rows, err := tx.QueryContext(ctx, "SELECT ip_address FROM ip_addresses WHERE host(ip_address) = any($1)", pq.Array(assignedAddresses))
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	for rows.Next() {
		var ipAddress string
		err = rows.Scan(&ipAddress)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		staticallyAllocatedAddressesSet.Add(net.ParseIP(ipAddress).String())
	}

	_ = tx.Commit()

	span.AddAttributes(
		trace.StringAttribute("assignedIPv4addresses", assignedIPv4addresses.String()),
		trace.StringAttribute("assignedIPv6addresses", assignedIPv6addresses.String()),
		trace.StringAttribute("utilizedAddressIPv4Set", utilizedAddressIPv4Set.String()),
		trace.StringAttribute("utilizedAddressIPv6Set", utilizedAddressIPv6Set.String()),
		trace.StringAttribute("staticallyAllocatedAddressesSet", staticallyAllocatedAddressesSet.String()),
	)
	entry.WithField("ipv4addresses", assignedIPv4addresses.ToSlice()).Debug("assigned IPv4 addresses")
	entry.WithField("ipv6addresses", assignedIPv6addresses.ToSlice()).Debug("assigned IPv6 addresses")
	entry.WithField("ipv4addresses", utilizedAddressIPv4Set.ToSlice()).Debug("utilized IPv4 addresses")
	entry.WithField("ipv6addresses", utilizedAddressIPv6Set.ToSlice()).Debug("utilized IPv6 addresses")
	entry.WithField("staticallyAllocatedAddressesSet", staticallyAllocatedAddressesSet.ToSlice()).Debug("statically allocated addresses")

	availableIPv4Addresses := assignedIPv4addresses.Difference(utilizedAddressIPv4Set).Difference(staticallyAllocatedAddressesSet)
	availableIPv6Addresses := assignedIPv6addresses.Difference(utilizedAddressIPv6Set).Difference(staticallyAllocatedAddressesSet)

	needIPv4Addresses := availableIPv4Addresses.Cardinality() == 0
	needIPv6Addresses := (req.Ipv6AddressRequested && availableIPv6Addresses.Cardinality() == 0)

	if !needIPv4Addresses && !needIPv6Addresses {
		_, ipnet, err := net.ParseCIDR(*subnet.CidrBlock)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot parse CIDR block")
		}
		prefixlength, _ := ipnet.Mask.Size()
		for addr := range assignedIPv4addresses.Difference(staticallyAllocatedAddressesSet).Iter() {
			response.UsableAddresses = append(response.UsableAddresses, &vpcapi.UsableAddress{
				Address:      &vpcapi.Address{Address: addr.(string)},
				PrefixLength: uint32(prefixlength),
			})
		}
		for addr := range assignedIPv6addresses.Difference(staticallyAllocatedAddressesSet).Iter() {
			response.UsableAddresses = append(response.UsableAddresses, &vpcapi.UsableAddress{
				Address: &vpcapi.Address{Address: addr.(string)},
				// AWS only assigns /128s?
				// This might be a problem for intra-subnet communication? Maybe?
				PrefixLength: uint32(128),
			})
		}
		return response, nil
	}
	entry.WithField("needIPv4Addresses", needIPv4Addresses).WithField("needIPv6Addresses", needIPv6Addresses).Info("NO IPs available, retrying allocation")

	if allowAssignment {
		if needIPv4Addresses {
			wantToAssignIPv4Addresses := 4
			if assignedIPv4addresses.Cardinality()+wantToAssignIPv4Addresses > maxIPAddresses {
				wantToAssignIPv4Addresses = maxIPAddresses - assignedIPv4addresses.Cardinality()
			}

			if wantToAssignIPv4Addresses <= 0 {
				return nil, errors.Errorf("Invalid number of IPv4 addresses to assign to interface: %d", wantToAssignIPv4Addresses)
			}

			assignPrivateIPAddressesInput := ec2.AssignPrivateIpAddressesInput{
				// TODO: Batch intelligently.
				SecondaryPrivateIpAddressCount: aws.Int64(int64(wantToAssignIPv4Addresses)),
				NetworkInterfaceId:             ni.NetworkInterfaceId,
			}
			if _, err := session.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput); err != nil {
				return nil, err
			}
		}

		if needIPv6Addresses {
			wantToAssignIPv6Addresses := 4
			if assignedIPv6addresses.Cardinality()+wantToAssignIPv6Addresses > maxIPAddresses {
				wantToAssignIPv6Addresses = maxIPAddresses - assignedIPv4addresses.Cardinality()
			}

			if wantToAssignIPv6Addresses <= 0 {
				return nil, errors.Errorf("Invalid number of IPv4 addresses to assign to interface: %d", wantToAssignIPv6Addresses)
			}

			assignIpv6AddressesInput := ec2.AssignIpv6AddressesInput{
				// TODO: Batch intelligently.
				Ipv6AddressCount:   aws.Int64(int64(wantToAssignIPv6Addresses)),
				NetworkInterfaceId: ni.NetworkInterfaceId,
			}

			if _, err := session.AssignIPv6Addresses(ctx, assignIpv6AddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
			}
		}
	}

	ni, err = session.GetNetworkInterfaceByID(ctx, aws.StringValue(ni.NetworkInterfaceId), time.Millisecond*100)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	return vpcService.assignAddresses(ctx, session, ni, req, subnet, maxIPAddresses, false)
}

func (vpcService *vpcService) getTrunkENI(instance *ec2.Instance) *ec2.InstanceNetworkInterface {
	for _, iface := range instance.NetworkInterfaces {
		if aws.StringValue(iface.InterfaceType) == "trunk" {
			return iface
		}
	}
	return nil
}

func (vpcService *vpcService) getBranchENI(ctx context.Context, tx *sql.Tx, key ec2wrapper.Key, subnetID string) (string, error) {
	var branchENI string
	rowContext := tx.QueryRowContext(ctx, "SELECT branch_enis.branch_eni FROM branch_enis JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni WHERE state = 'unattached' AND subnet_id = $1 FOR UPDATE LIMIT 1", subnetID)
	err := rowContext.Scan(&branchENI)
	if err == nil {
		return branchENI, nil
	}

	createNetworkInterfaceInput := &ec2.CreateNetworkInterfaceInput{
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         aws.String(subnetID),
		Description:      aws.String(vpc.BranchNetworkInterfaceDescription),
	}
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, key)
	if err != nil {
		return "", err
	}

	ec2client := ec2.New(session.Session)
	createNetworkInterfaceOutput, err := ec2client.CreateNetworkInterface(createNetworkInterfaceInput)
	if err != nil {
		return "", err
	}

	_, err = tx.ExecContext(ctx, "INSERT INTO branch_enis (branch_eni, subnet_id, account_id, az, vpc_id) VALUES ($1, $2, $3, $4, $5)",
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.SubnetId),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.OwnerId),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.AvailabilityZone),
		aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.VpcId),
	)
	if err != nil {
		return "", err
	}

	return aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId), nil
}

// ctx, tx, ec2client, trunkENI, accountID,  int(req.NetworkInterfaceAttachment.DeviceIndex)
func (vpcService *vpcService) ensureBranchENIAttached(ctx context.Context, ec2client *ec2.EC2, trunkInterface *ec2.InstanceNetworkInterface, accountID, availabilityZone string, idx int) (eniID string, retErr error) {
	//	row := tx.QueryRowContext(ctx, "SELECT branch_eni FROM branch_eni_attachments WHERE idx = $1 AND trunk_eni = $2", idx, aws.StringValue(trunkInterface))
	// TODO: Handle detaching
	ctx, span := trace.StartSpan(ctx, "ensureBranchENIAttached")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return "", err
	}
	defer func() {
		// TODO: return error if transaction fails
		if retErr == nil {
			retErr = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}()

	rowContext := tx.QueryRowContext(ctx, "SELECT subnet_id, vpc_id FROM account_mapping WHERE account = $1 AND availability_zone = $2", accountID, availabilityZone)
	var subnetID, vpcID string
	err = rowContext.Scan(&subnetID, &vpcID)
	if err == sql.ErrNoRows {
		err = errors.Wrapf(err, "Not rows found in account mappings table for AZ %q and account %q", availabilityZone, accountID)
		span.SetStatus(traceStatusFromError(err))
		return "", err
	} else if err != nil {
		err = errors.Wrap(err, "Could not fetch account mappings")
		span.SetStatus(traceStatusFromError(err))
		return "", err
	}

	if accountID != aws.StringValue(trunkInterface.OwnerId) {
		return "", fmt.Errorf("Branch ENI in account ID %q whereas trunk ENI interface owner ID %q not supported", accountID, aws.StringValue(trunkInterface.NetworkInterfaceId))
	}

	// Do we already have a branch ENI attached here?
	rowContext = tx.QueryRowContext(ctx, "SELECT branch_enis.branch_eni, account_id, subnet_id FROM branch_enis JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni WHERE state = 'attached' AND idx = $1 AND trunk_eni = $2", idx, aws.StringValue(trunkInterface.NetworkInterfaceId))
	var branchENI, branchENIAccountID, branchENISubnetID string
	err = rowContext.Scan(&branchENI, &branchENIAccountID, &branchENISubnetID)
	if err == nil {
		if branchENIAccountID != accountID {
			return "", fmt.Errorf("Branch ENI in account ID %q, whereas want account ID %q", branchENIAccountID, accountID)
		}
		if branchENISubnetID != subnetID {
			return "", fmt.Errorf("Branch ENI in subnet ID %q, whereas want subnet ID %q", branchENISubnetID, subnetID)
		}
		return branchENI, nil
	}
	if err != sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(err))
		return "", err
	}

	// TODO: Pass the ec2client for the "destination" account ID
	region := availabilityZone[:len(availabilityZone)-1]
	branchENI, err = vpcService.getBranchENI(ctx, tx, ec2wrapper.Key{AccountID: accountID, Region: region}, subnetID)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return "", err
	}

	associateTrunkInterfaceInput := &ec2.AssociateTrunkInterfaceInput{
		BranchInterfaceId: aws.String(branchENI),
		TrunkInterfaceId:  trunkInterface.NetworkInterfaceId,
		VlanId:            aws.Int64(int64(idx)),
	}

	associateTrunkInterfaceOutput, err := ec2client.AssociateTrunkInterfaceWithContext(ctx, associateTrunkInterfaceInput)
	if err != nil {
		return "", err
	}
	logger.G(ctx).Debug(associateTrunkInterfaceOutput)
	_, err = tx.ExecContext(ctx, "INSERT INTO branch_eni_attachments(branch_eni, state, trunk_eni, idx) VALUES ($1, 'attached', $2, $3) ON CONFLICT (branch_eni) DO UPDATE SET state = 'attached', trunk_eni = $2, idx = $3",
		branchENI,
		aws.StringValue(trunkInterface.NetworkInterfaceId),
		idx)
	if err != nil {
		return "", errors.Wrap(err, "Unable to update branch_eni attachments")
	}
	// TODO: Create network interface permission if necessary
	return branchENI, nil
}

func (vpcService *vpcService) ensureSecurityGroups(ctx context.Context, ec2client *ec2.EC2, eni *ec2.NetworkInterface, securityGroupIDs []string, allowSecurityGroupChange bool) error {
	ctx, span := trace.StartSpan(ctx, "ensureSecurityGroups")
	defer span.End()

	wantedSecurityGroupsSet := sets.NewString(securityGroupIDs...)
	hasSecurityGroupsSet := sets.NewString()
	for _, group := range eni.Groups {
		hasSecurityGroupsSet.Insert(*group.GroupId)
	}

	span.AddAttributes(trace.StringAttribute("currentSecurityGroups", fmt.Sprint(hasSecurityGroupsSet.List())))
	span.AddAttributes(trace.StringAttribute("newSecurityGroups", fmt.Sprint(wantedSecurityGroupsSet.List())))
	logger.G(ctx).
		WithField("currentSecurityGroups", hasSecurityGroupsSet.List()).
		WithField("newSecurityGroups", wantedSecurityGroupsSet.List()).
		Info("Changing security groups")

	if !wantedSecurityGroupsSet.Equal(hasSecurityGroupsSet) {
		if !allowSecurityGroupChange {
			err := status.Error(codes.FailedPrecondition, "Security group change required, but not allowed")
			span.SetStatus(traceStatusFromError(err))
			return err
		}
	}
	modifyNetworkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             aws.StringSlice(wantedSecurityGroupsSet.List()),
		NetworkInterfaceId: eni.NetworkInterfaceId,
	}
	_, err := ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, modifyNetworkInterfaceAttributeInput)
	return ec2wrapper.HandleEC2Error(err, span)
}

func assignSpecificIPv4Address(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, branchENI *ec2.NetworkInterface, ipnet *net.IPNet, alloc *vpcapi.AssignIPRequestV2_Ipv4SignedAddressAllocation) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignSpecificIPv4Address")
	defer span.End()
	prefixlength, _ := ipnet.Mask.Size()

	row := tx.QueryRowContext(ctx, "SELECT ip_address FROM ip_addresses WHERE id = $1", alloc.Ipv4SignedAddressAllocation.AddressAllocation.Uuid)
	var ip string
	err := row.Scan(&ip)
	if err == sql.ErrNoRows {
		err = errors.Wrapf(err, "Could not find allocation")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Could not fetch allocations from database")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		PrivateIpAddresses: aws.StringSlice([]string{ip}),
		AllowReassignment:  aws.Bool(true),
	}
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

func assignArbitraryIPv6Address(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, branchENI *ec2.NetworkInterface, instance *ec2.Instance, utilizedAddresses []*vpcapi.UtilizedAddress) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignArbitraryIPv4Address")
	defer span.End()

	maxIPAddresses, err := vpc.GetMaxIPAddresses(aws.StringValue(instance.InstanceType))
	if err != nil {
		err = status.Error(codes.InvalidArgument, err.Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	usedIPv6Addresses := sets.NewString()
	for _, address := range utilizedAddresses {
		ip := net.ParseIP(address.Address.Address)
		ipStr := ip.String()
		if ip.To4() == nil {
			usedIPv6Addresses.Insert(ipStr)
		}
	}

	interfaceIPv6Addresses := sets.NewString()
	for _, addr := range branchENI.Ipv6Addresses {
		interfaceIPv6Addresses.Insert(net.ParseIP(aws.StringValue(addr.Ipv6Address)).String())
	}

	if l := usedIPv6Addresses.Len(); l >= maxIPAddresses {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv6 addresses already in-use", l)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	unusedIPv6Addresses := interfaceIPv6Addresses.Difference(usedIPv6Addresses)
	if unusedIPv6Addresses.Len() > 0 {
		unusedIPv6AddressesList := unusedIPv6Addresses.List()
		rows, err := tx.QueryContext(ctx, "SELECT ip_address, last_used FROM ip_last_used WHERE host(ip_address) = any($1)", pq.Array(unusedIPv6AddressesList))
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not fetch utilized IPv4 addresses from the database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		ipToTimeLastUsed := map[string]time.Time{}
		epoch := time.Time{}
		for addr := range unusedIPv6Addresses {
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
		_ = rows.Close()

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
	ipsToAssign := maxIPAddresses - usedIPv6Addresses.Len()
	if ipsToAssign <= 0 {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv6 addresses already assigned", usedIPv6Addresses.Len())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if ipsToAssign > 4 {
		ipsToAssign = 4
	}
	assignIpv6AddressesInput := &ec2.AssignIpv6AddressesInput{
		NetworkInterfaceId: branchENI.NetworkInterfaceId,
		Ipv6AddressCount:   aws.Int64(int64(ipsToAssign)),
	}
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

func assignArbitraryIPv4Address(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, branchENI *ec2.NetworkInterface, ipnet *net.IPNet, instance *ec2.Instance, utilizedAddresses []*vpcapi.UtilizedAddress) (*vpcapi.UsableAddress, error) {
	ctx, span := trace.StartSpan(ctx, "assignArbitraryIPv4Address")
	defer span.End()
	prefixlength, _ := ipnet.Mask.Size()

	maxIPAddresses, err := vpc.GetMaxIPAddresses(aws.StringValue(instance.InstanceType))
	if err != nil {
		err = status.Error(codes.InvalidArgument, err.Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	usedIPv4Addresses := sets.NewString()

	for _, address := range utilizedAddresses {
		ip := net.ParseIP(address.Address.Address)
		ipStr := ip.String()
		if ip.To4() != nil {
			usedIPv4Addresses.Insert(ipStr)
		}
	}

	if l := usedIPv4Addresses.Len(); l >= maxIPAddresses {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses already in-use", l)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	interfaceIPv4Addresses := sets.NewString()
	for _, addr := range branchENI.PrivateIpAddresses {
		interfaceIPv4Addresses.Insert(net.ParseIP(aws.StringValue(addr.PrivateIpAddress)).String())
	}

	unusedIPv4Addresses := interfaceIPv4Addresses.Difference(usedIPv4Addresses)

	if unusedIPv4Addresses.Len() > 0 {
		rows, err := tx.QueryContext(ctx, "SELECT ip_address FROM ip_addresses WHERE host(ip_address) = any($1)", pq.Array(unusedIPv4Addresses.List()))
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not fetch utilized IPv4 addresses from the database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		for rows.Next() {
			var ip string
			err = rows.Scan(&ip)
			if err != nil {
				err = status.Error(codes.Unknown, errors.Wrap(err, "Could not scan utilized IPv4 addresses from the database").Error())
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
			unusedIPv4Addresses.Delete(net.ParseIP(ip).String())
		}
		_ = rows.Close()
	}
	if unusedIPv4Addresses.Len() > 0 {
		unusedIPv4AddressesList := unusedIPv4Addresses.List()

		rows, err := tx.QueryContext(ctx, "SELECT ip_address, last_used FROM ip_last_used WHERE host(ip_address) = any($1)", pq.Array(unusedIPv4AddressesList))
		if err != nil {
			err = status.Error(codes.Unknown, errors.Wrap(err, "Could not fetch utilized IPv4 addresses from the database").Error())
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}

		ipToTimeLastUsed := map[string]time.Time{}
		epoch := time.Time{}
		for addr := range unusedIPv4Addresses {
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
		_ = rows.Close()

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
	ipsToAssign := maxIPAddresses - usedIPv4Addresses.Len()
	if ipsToAssign <= 0 {
		err = status.Errorf(codes.FailedPrecondition, "%d IPv4 addresses already assigned", usedIPv4Addresses.Len())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if ipsToAssign > 4 {
		ipsToAssign = 4
	}
	assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             branchENI.NetworkInterfaceId,
		SecondaryPrivateIpAddressCount: aws.Int64(int64(ipsToAssign)),
	}
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

func (vpcService *vpcService) AssignIPV2(ctx context.Context, req *vpcapi.AssignIPRequestV2) (_ *vpcapi.AssignIPResponseV2, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssignIPv2")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
		trace.StringAttribute("securityGroupIds", fmt.Sprint(req.SecurityGroupIds)),
		trace.StringAttribute("allowSecurityGroupChange", fmt.Sprint(req.AllowSecurityGroupChange)),
		trace.Int64Attribute("deviceIdx", int64(req.GetNetworkInterfaceAttachment().DeviceIndex)),
	)

	usedIPv4Addresses := sets.NewString()
	usedIPv6Addresses := sets.NewString()

	for _, address := range req.UtilizedAddresses {
		ip := net.ParseIP(address.Address.Address)
		ipStr := ip.String()
		if ip.To4() == nil {
			usedIPv6Addresses.Insert(ipStr)
		} else {
			usedIPv4Addresses.Insert(ipStr)
		}
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: req.InstanceIdentity.Region, AccountID: req.InstanceIdentity.AccountID})
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	instance, _, err := session.GetInstance(ctx, req.InstanceIdentity.InstanceID, ec2wrapper.UseCache)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	trunkENI := vpcService.getTrunkENI(instance)
	if trunkENI == nil {
		err = status.Error(codes.FailedPrecondition, "Instance does not have trunk ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	accountID := req.AccountID
	if accountID == "" {
		accountID = aws.StringValue(trunkENI.OwnerId)
	}
	az := aws.StringValue(instance.Placement.AvailabilityZone)
	ec2client := ec2.New(session.Session)
	// TODO: Sargun, break out into its own transaction
	branchENI, err := vpcService.ensureBranchENIAttached(ctx, ec2client, trunkENI, accountID, az, int(req.NetworkInterfaceAttachment.DeviceIndex))
	if err != nil {
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
		// TODO: return error if transaction fails
		if retErr == nil {
			retErr = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}()
	_, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock_shared(oid::int, branch_enis.id) FROM branch_enis, (SELECT oid FROM pg_class WHERE relname = 'branch_enis') o WHERE branch_eni = $1",
		branchENI)
	if err != nil {
		return nil, err
	}

	ec2BranchENI, err := session.GetNetworkInterfaceByID(ctx, branchENI, 100*time.Millisecond)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = vpcService.ensureSecurityGroups(ctx, ec2client, ec2BranchENI, req.SecurityGroupIds, req.AllowSecurityGroupChange)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	subnet, err := session.GetSubnetByID(ctx, aws.StringValue(ec2BranchENI.SubnetId), ec2wrapper.UseCache)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	_, ipnet, err := net.ParseCIDR(aws.StringValue(subnet.CidrBlock))
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	resp := vpcapi.AssignIPResponseV2{}
	switch ipv4req := (req.Ipv4).(type) {
	case *vpcapi.AssignIPRequestV2_Ipv4SignedAddressAllocation:
		resp.Ipv4Address, err = assignSpecificIPv4Address(ctx, tx, ec2client, ec2BranchENI, ipnet, ipv4req)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	case *vpcapi.AssignIPRequestV2_Ipv4AddressRequested:
		if ipv4req.Ipv4AddressRequested {
			resp.Ipv4Address, err = assignArbitraryIPv4Address(ctx, tx, ec2client, ec2BranchENI, ipnet, instance, req.UtilizedAddresses)

			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used (ip_address, last_allocated) VALUES ($1, CURRENT_TIMESTAMP) ON CONFLICT (ip_address) DO UPDATE SET last_allocated = CURRENT_TIMESTAMP", resp.Ipv4Address.Address.Address)
			if err != nil {
				return nil, err
			}
		}
	}

	switch ipv6req := (req.Ipv6).(type) {
	case *vpcapi.AssignIPRequestV2_Ipv6AddressRequested:
		if ipv6req.Ipv6AddressRequested {
			resp.Ipv6Address, err = assignArbitraryIPv6Address(ctx, tx, ec2client, ec2BranchENI, instance, req.UtilizedAddresses)

			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				return nil, err
			}
			_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used (ip_address, last_allocated) VALUES ($1, CURRENT_TIMESTAMP) ON CONFLICT (ip_address) DO UPDATE SET last_allocated = CURRENT_TIMESTAMP", resp.Ipv6Address.Address.Address)
			if err != nil {
				return nil, err
			}
		}
	}

	resp.BranchNetworkInterface = networkInterface(*ec2BranchENI)
	resp.TrunkNetworkInterface = instanceNetworkInterface(*instance, *trunkENI)
	resp.VlanId = req.NetworkInterfaceAttachment.DeviceIndex
	logger.G(ctx).Debug(resp)

	return &resp, nil
}

func (vpcService *vpcService) RefreshIP(ctx context.Context, request *vpcapi.RefreshIPRequest) (*vpcapi.RefreshIPResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "RefreshIP")
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

	for _, addr := range request.UtilizedAddress {
		ts, err := ptypes.Timestamp(addr.LastUsedTime)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Cannot parse timestamp")
			continue
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO ip_last_used(ip_address, last_used) VALUES($1, $2) ON CONFLICT(ip_address) DO UPDATE SET last_used = $2", addr.Address.Address, ts)
		if err != nil {
			err = errors.Wrap(err, "Could not update ip_last_used table")
			return nil, err
		}
	}
	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit refresh")
		return nil, err
	}
	return &vpcapi.RefreshIPResponse{
		NextRefresh: ptypes.DurationProto(vpc.RefreshInterval),
	}, nil
}
