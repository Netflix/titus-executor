package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	ec2InstanceSession, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	instance, err := ec2InstanceSession.GetInstance(ctx, ec2wrapper.UseCache)
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

	interfaceSession, err := ec2InstanceSession.GetInterfaceByIdx(ctx, req.NetworkInterfaceAttachment.DeviceIndex)
	if err != nil {
		if ec2wrapper.IsErrInterfaceByIdxNotFound(err) {
			err = status.Error(codes.NotFound, err.Error())
		}
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	span.AddAttributes(trace.StringAttribute("eni", interfaceSession.ElasticNetworkInterfaceID()))
	ctx = logger.WithField(ctx, "eni", interfaceSession.ElasticNetworkInterfaceID())

	subnet, err := interfaceSession.GetSubnet(ctx, ec2wrapper.UseCache)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	iface, err := interfaceSession.GetNetworkInterface(ctx, time.Millisecond*100)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	// TODO: Validate these
	wantedSecurityGroups := aws.StringSlice(req.GetSecurityGroupIds())
	// Assign default security groups
	if len(wantedSecurityGroups) == 0 {
		wantedSecurityGroups, err = interfaceSession.GetDefaultSecurityGroups(ctx)
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
		err = interfaceSession.ModifySecurityGroups(ctx, wantedSecurityGroups)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
	}

	if len(req.SignedAddressAllocations) > 0 {
		logger.G(ctx).Debug("Performing static address allocation")
		return vpcService.assignAddressesFromAllocations(ctx, interfaceSession, iface, subnet, req)
	}

	return vpcService.assignAddresses(ctx, interfaceSession, iface, req, subnet, maxIPAddresses, true)
}

func (vpcService *vpcService) assignAddressesFromAllocations(ctx context.Context, iface ec2wrapper.EC2NetworkInterfaceSession, ni *ec2.NetworkInterface, subnet *ec2.Subnet, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
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
		}
		for idx := range ipv4AddressesToAssign {
			assignPrivateIPAddressesInput.PrivateIpAddresses[idx] = aws.String(ipv4AddressesToAssign[idx].String())
		}
		logger.G(ctx).WithField("ipv4AddressesToAssign", ipv4AddressesToAssign).Debug("Assigning static IPv4 Addresses")
		if _, err := iface.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput); err != nil {
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}
	}

	if len(ipv6AddressesToAssign) > 0 {
		logger.G(ctx).WithField("ipv6AddressesToAssign", ipv6AddressesToAssign).Debug("Assigning IPv6 Addresses")
		assignIpv6AddressesInput := ec2.AssignIpv6AddressesInput{
			Ipv6Addresses: make([]*string, len(ipv6AddressesToAssign)),
		}
		for idx := range ipv6AddressesToAssign {
			assignIpv6AddressesInput.Ipv6Addresses[idx] = aws.String(ipv6AddressesToAssign[idx].String())
		}
		logger.G(ctx).WithField("ipv6AddressesToAssign", ipv4AddressesToAssign).Debug("Assigning static IPv6 Addresses")
		if _, err := iface.AssignIPv6Addresses(ctx, assignIpv6AddressesInput); err != nil {
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}
	}

	ni, err = iface.GetNetworkInterface(ctx, time.Millisecond*100)
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

func (vpcService *vpcService) assignAddresses(ctx context.Context, iface ec2wrapper.EC2NetworkInterfaceSession, ni *ec2.NetworkInterface, req *vpcapi.AssignIPRequest, subnet *ec2.Subnet, maxIPAddresses int, allowAssignment bool) (*vpcapi.AssignIPResponse, error) {
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
			}
			if _, err := iface.AssignPrivateIPAddresses(ctx, assignPrivateIPAddressesInput); err != nil {
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
				Ipv6AddressCount: aws.Int64(int64(wantToAssignIPv6Addresses)),
			}

			if _, err := iface.AssignIPv6Addresses(ctx, assignIpv6AddressesInput); err != nil {
				return nil, status.Convert(errors.Wrap(err, "Cannot assign IPv6 addresses")).Err()
			}
		}
	}

	ni, err = iface.GetNetworkInterface(ctx, time.Millisecond*100)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	return vpcService.assignAddresses(ctx, iface, ni, req, subnet, maxIPAddresses, false)
}
