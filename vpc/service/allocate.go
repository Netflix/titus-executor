package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	"github.com/lib/pq"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// this is the maximum number of IP addresses you are allowed to assign to an interface in EC2.
const maxAddressesPerInterface = 50

// The dummy interface is used for IP addresses that are allocated
const (
	staticDummyInterfaceDescription = "titus-static-dummy"
	tmpDummyInterfaceDescription    = "titus-tmp-dummy"
	staticReservationDescription    = "titus-static-address"
)

var (
	errAllocationNotFound = status.Error(codes.NotFound, "Could not find allocation")
	errConsistencyIssue   = status.Error(codes.Unknown, "Database state inconsistent, no IPs available on ENI")
)

func (vpcService *vpcService) getStaticInterface(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, subnetID string) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "getStaticInterface")
	defer span.End()

	var eniID string
	// We can't use the first address, maxAddressesPerInterface - 1
	row := tx.QueryRowContext(ctx, "SELECT eni_id FROM static_enis WHERE subnet_id = $1 AND (SELECT count(*) FROM ip_addresses WHERE home_eni = static_enis.eni_id) < $2 FOR UPDATE LIMIT 1", subnetID, maxAddressesPerInterface-1)
	err := row.Scan(&eniID)
	if err != nil && err != sql.ErrNoRows {
		err = errors.Wrap(err, "Cannot fetch ENI from static enis set")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ec2client := ec2.New(session.Session)

	if err == nil {
		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &ec2.DescribeNetworkInterfacesInput{
			NetworkInterfaceIds: aws.StringSlice([]string{eniID}),
		})
		if err != nil {
			return nil, ec2wrapper.HandleEC2Error(err, span)
		}
		if l := len(describeNetworkInterfacesOutput.NetworkInterfaces); l != 1 {
			err = fmt.Errorf("Unexpected number of interfaces returned from DescribeNetworkInterfacesWithContext: %d", l)
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		return describeNetworkInterfacesOutput.NetworkInterfaces[0], nil
	}

	createNetworkInterfaceOutput, err := ec2client.CreateNetworkInterfaceWithContext(ctx, &ec2.CreateNetworkInterfaceInput{
		Description:                    aws.String(staticDummyInterfaceDescription),
		SubnetId:                       aws.String(subnetID),
		Ipv6AddressCount:               aws.Int64(maxAddressesPerInterface),
		SecondaryPrivateIpAddressCount: aws.Int64(maxAddressesPerInterface - 1),
	})
	if err != nil && err != sql.ErrNoRows {
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	eniID = aws.StringValue(createNetworkInterfaceOutput.NetworkInterface.NetworkInterfaceId)
	_, err = tx.ExecContext(ctx, "INSERT INTO static_enis(eni_id, subnet_id) VALUES ($1, $2)", eniID, subnetID)
	if err != nil {
		err = errors.Wrap(err, "Unable to save newly statically created ENI")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return createNetworkInterfaceOutput.NetworkInterface, nil
}

func (vpcService *vpcService) AllocateAddress(ctx context.Context, rq *titus.AllocateAddressRequest) (*titus.AllocateAddressResponse, error) {
	// 1. We get the subnet
	// 2. We allocate an IP
	// 3. Do the cryptography dance
	// 4. Store it in the database.
	// 5. Return it to the user
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "allocateAddress")
	defer span.End()

	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	if rq.AccountId == "" {
		return nil, status.Error(codes.InvalidArgument, "AccountId must be specified")
	}
	if rq.AddressAllocation == nil {
		return nil, status.Error(codes.InvalidArgument, "AddressAllocation must be specified")
	}
	if rq.AddressAllocation.AddressLocation == nil {
		return nil, status.Error(codes.InvalidArgument, "AddressAllocation.AddressLocation must be specified")
	}

	if rq.AddressAllocation.Address != "" {
		return nil, status.Error(codes.InvalidArgument, "AddressAllocation.Address must be unset")
	}

	if rq.Family != titus.Family_FAMILY_V4 {
		return nil, status.Errorf(codes.Unimplemented, "Address family %s not yet implemented", rq.Family.String())
	}

	if rq.AddressAllocation.AddressLocation.SubnetId == "" {
		return nil, status.Error(codes.InvalidArgument, "Subnet ID must be specified")
	}

	allocationUUID := rq.AddressAllocation.Uuid
	if allocationUUID == "" {
		allocationUUID = uuid.New().String()
	}

	logger.WithFields(ctx, map[string]interface{}{
		"family":   rq.Family,
		"region":   rq.AddressAllocation.AddressLocation.Region,
		"az":       rq.AddressAllocation.AddressLocation.AvailabilityZone,
		"subnetID": rq.AddressAllocation.AddressLocation.SubnetId,
	})
	logger.G(ctx).Info("Performing Address allocation")

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = tx.ExecContext(ctx, "INSERT INTO ip_addresses (id) VALUES ($1)", allocationUUID)
	if err != nil {
		err = errors.Wrapf(err, "Cannot insert allocation record for UUID %s", allocationUUID)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row := tx.QueryRowContext(ctx, "SELECT az, vpc_id, account_id FROM subnets WHERE subnet_id = $1", rq.AddressAllocation.AddressLocation.SubnetId)
	var az, vpcID, accountID string
	err = row.Scan(&az, &vpcID, &accountID)
	if err == sql.ErrNoRows {
		err = status.Errorf(codes.NotFound, "Could not find subnet ID %s", rq.AddressAllocation.AddressLocation.SubnetId)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot query subnet")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	region := azToRegionRegexp.FindString(az)
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		Region:    region,
		AccountID: accountID,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	iface, err := vpcService.getStaticInterface(ctx, tx, session, rq.AddressAllocation.AddressLocation.SubnetId)
	if err != nil {
		err = errors.Wrap(err, "Cannot get static interface")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	knownAddresses := []string{}
	for _, addr := range iface.PrivateIpAddresses {
		if !aws.BoolValue(addr.Primary) {
			knownAddresses = append(knownAddresses, aws.StringValue(addr.PrivateIpAddress))
		}
	}

	knownIPv6Addresses := []string{}
	for _, addr := range iface.Ipv6Addresses {
		knownIPv6Addresses = append(knownIPv6Addresses, aws.StringValue(addr.Ipv6Address))
	}

	row = tx.QueryRowContext(ctx, `
WITH interface_ip_addresses AS
  (SELECT unnest($1::text[])::INET AS ip_address)
SELECT ip_address
FROM interface_ip_addresses
WHERE interface_ip_addresses.ip_address NOT IN
    (SELECT ip_address
     FROM ip_addresses
     WHERE subnet_id = $2)
LIMIT 1
`, pq.Array(knownAddresses), aws.StringValue(iface.SubnetId))
	var ipAddress string
	err = row.Scan(&ipAddress)
	if err == sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(errConsistencyIssue))
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to get free IP address")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row = tx.QueryRowContext(ctx, `
WITH interface_ipv6_addresses AS
  (SELECT unnest($1::text[])::INET AS ipv6_address)
SELECT ipv6_address
FROM interface_ipv6_addresses
WHERE interface_ipv6_addresses.ipv6_address NOT IN
    (SELECT ipv6address
     FROM ip_addresses
     WHERE subnet_id = $2)
LIMIT 1
`, pq.Array(knownIPv6Addresses), aws.StringValue(iface.SubnetId))
	var ipv6Address string
	err = row.Scan(&ipv6Address)
	if err == sql.ErrNoRows {
		span.SetStatus(traceStatusFromError(errConsistencyIssue))
		return nil, err
	}
	if err != nil {
		err = errors.Wrap(err, "Unable to get free IP address")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	addressAllocation := &titus.AddressAllocation{
		AddressLocation: &titus.AddressLocation{
			Region:           region,
			AvailabilityZone: az,
			SubnetId:         aws.StringValue(iface.SubnetId),
		},
		Uuid:    allocationUUID,
		Address: ipAddress,
	}

	bytes, err := proto.Marshal(addressAllocation)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot serialize allocation")
	}

	signature := ed25519.Sign(vpcService.hostPrivateKey, bytes)

	_, err = tx.ExecContext(ctx,
		`
UPDATE ip_addresses SET 
                        az = $2, 
                        region = $3, 
                        subnet_id = $4,
                        ip_address = $5,
						ipv6address = $6,
                        home_eni = $7,
                        host_public_key = $8,
                        host_public_key_signature = $9,
                        message = $10,
                        message_signature = $11,
                        account = $12
WHERE id = $1`,
		allocationUUID,
		az,
		region,
		aws.StringValue(iface.SubnetId),
		ipAddress,
		ipv6Address,
		aws.StringValue(iface.NetworkInterfaceId),
		vpcService.hostPublicKey,
		vpcService.hostPublicKeySignature,
		bytes,
		signature,
		accountID,
	)
	if err != nil {
		return nil, errors.Wrap(err, "Could not persist allocation")
	}
	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Could not commit transaction")
	}

	err = vpcService.fixAllocation(ctx, allocation{
		id:      allocationUUID,
		region:  region,
		subnet:  aws.StringValue(iface.SubnetId),
		account: accountID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Could not create subnet cidr reservations")
	}

	_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: iface.NetworkInterfaceId,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not delete static network interface")
	}

	resp := &titus.AllocateAddressResponse{
		SignedAddressAllocation: &titus.SignedAddressAllocation{
			AddressAllocation:      addressAllocation,
			AuthoritativePublicKey: vpcService.authoritativePublicKey,
			HostPublicKey:          vpcService.hostPublicKey,
			HostPublicKeySignature: vpcService.hostPublicKeySignature,
			Message:                bytes,
			MessageSignature:       signature,
		},
	}

	return resp, nil
}

func (vpcService *vpcService) GetAllocation(ctx context.Context, rq *titus.GetAllocationRequest) (*titus.GetAllocationResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	var rows *sql.Rows
	var err error
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	switch v := rq.GetSearchParameter().(type) {
	case *titus.GetAllocationRequest_Address:
		rows, err = tx.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address, host_public_key, host_public_key_signature, message, message_signature FROM ip_addresses WHERE ip_address = $1", v.Address)

	case *titus.GetAllocationRequest_Uuid:
		rows, err = tx.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address, host_public_key, host_public_key_signature, message, message_signature FROM ip_addresses WHERE id = $1", v.Uuid)
	}
	if err != nil {
		return nil, errors.Wrap(err, "Could not run SQL query")
	}

	if !rows.Next() {
		return nil, errAllocationNotFound
	}
	var id, az, region, subnetid, ipaddress string
	var hostPublicKey, hostPublicKeySignature, message, messageSignature []byte
	err = rows.Scan(&id, &az, &region, &subnetid, &ipaddress, &hostPublicKey, &hostPublicKeySignature, &message, &messageSignature)
	if err == sql.ErrNoRows {
		return nil, errAllocationNotFound
	}
	if err != nil {
		return nil, errors.Wrap(err, "Could not deserialize row")
	}

	var trustedPublicKey ed25519.PublicKey
	rows, err = vpcService.db.QueryContext(ctx, "SELECT key FROM trusted_public_keys")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		err = rows.Scan(&trustedPublicKey)
		if err != nil {
			return nil, err
		}
		if ed25519.Verify(trustedPublicKey, hostPublicKey, hostPublicKeySignature) {
			goto key_found
		}
	}
	return nil, status.Error(codes.NotFound, "Could not find authoritative public key for record")

key_found:

	allocation := &titus.AddressAllocation{
		AddressLocation: &titus.AddressLocation{
			Region:           region,
			AvailabilityZone: az,
			SubnetId:         subnetid,
		},
		Uuid:    id,
		Address: ipaddress,
	}

	return &titus.GetAllocationResponse{
		AddressAllocation: allocation,
		SignedAddressAllocation: &titus.SignedAddressAllocation{
			AuthoritativePublicKey: trustedPublicKey,
			AddressAllocation:      allocation,
			HostPublicKey:          hostPublicKey,
			HostPublicKeySignature: hostPublicKeySignature,
			Message:                message,
			MessageSignature:       messageSignature,
		},
	}, nil
}

func (vpcService *vpcService) ValidateAllocation(ctx context.Context, req *titus.ValidationRequest) (*titus.ValidationResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, "SELECT count(*) FROM trusted_public_keys WHERE key = $1", req.SignedAddressAllocation.AuthoritativePublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "Could not run database query for authoritative public key")
	}
	if !rows.Next() {
		return nil, status.Error(codes.Internal, "Failed to run SQL query")
	}
	var count int
	err = rows.Scan(&count)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to fetch public key count")
	}
	if count == 0 {
		return nil, status.Error(codes.NotFound, "authoritative public key not found")
	}

	verify := ed25519.Verify(req.SignedAddressAllocation.AuthoritativePublicKey, req.SignedAddressAllocation.HostPublicKey, req.SignedAddressAllocation.HostPublicKeySignature)
	if !verify {
		return nil, status.Error(codes.InvalidArgument, "Unable to validate host signature")
	}

	verify = ed25519.Verify(req.SignedAddressAllocation.HostPublicKey, req.SignedAddressAllocation.Message, req.SignedAddressAllocation.MessageSignature)
	if !verify {
		return nil, status.Error(codes.InvalidArgument, "Unable to validate message signature")
	}

	var addressAllocation titus.AddressAllocation

	err = proto.Unmarshal(req.SignedAddressAllocation.Message, &addressAllocation)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, errors.Wrap(err, "Unable to decode message").Error())
	}

	if !proto.Equal(&addressAllocation, req.SignedAddressAllocation.AddressAllocation) {
		return nil, status.Error(codes.InvalidArgument, "Address allocation has  been tampered with")
	}

	return &titus.ValidationResponse{}, nil
}

type allocation struct {
	id      string
	region  string
	account string
	subnet  string
}

func (vpcService *vpcService) FixOldAllocations(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx,
		`SELECT 
       ip_addresses.id, ip_addresses.region, subnets.account_id, ip_addresses.subnet_id 
FROM ip_addresses 
JOIN subnets ON ip_addresses.subnet_id = subnets.subnet_id
WHERE ipv6address IS NULL`)
	if err != nil {
		return fmt.Errorf("Could not query IDs from ip_addresses: %w", err)
	}

	var allocations []allocation
	for rows.Next() {
		var alloc allocation
		err = rows.Scan(&alloc.id, &alloc.region, &alloc.account, &alloc.subnet)
		if err != nil {
			return fmt.Errorf("Could not scan row: %w", err)
		}

		allocations = append(allocations, alloc)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Cannot commit transaction to get outstanding, unconverted records: %w", err)
	}

	for _, alloc := range allocations {
		err = vpcService.fixAllocation(ctx, alloc)
		if err != nil {
			return fmt.Errorf("Could not fix allocation %s: %w", alloc.id, err)
		}
		break
	}

	return nil
}

func (vpcService *vpcService) fixAllocation(ctx context.Context, alloc allocation) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: alloc.account,
		Region:    alloc.region,
	})
	if err != nil {
		return fmt.Errorf("Cannot get session: %w", err)
	}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var ipv4addr string
	var ipv6addr sql.NullString
	row := tx.QueryRowContext(ctx,
		"SELECT ip_address, ipv6address FROM ip_addresses WHERE id = $1 FOR NO KEY UPDATE",
		alloc.id,
	)
	err = row.Scan(&ipv4addr, &ipv6addr)
	if err != nil {
		return fmt.Errorf("Cannot scan ip addresses: %w", err)
	}
	v4addr := net.ParseIP(ipv4addr)
	v6addr := net.ParseIP(ipv6addr.String)
	// if !ipv6addr.Valid {
	// 	// We need to backfill the IPv6 address
	// 	v6addr, err = assignNextIPv6Address(ctx, tx, alloc.subnet)
	// 	if err != nil {
	// 		return fmt.Errorf("Could not assign next IPv6 address: %w", err)
	// 	}
	// 	_, err = tx.ExecContext(ctx, "UPDATE ip_addresses SET ipv6address = $1 WHERE id = $2", v6addr.String(), alloc.id)
	// 	if err != nil {
	// 		return fmt.Errorf("Could not update ipv6addr: %w", err)
	// 	}
	// }

	v6output, err := session.CreateSubnetCidrReservation(ctx, ec2.CreateSubnetCidrReservationInput{
		Cidr:            aws.String(fmt.Sprintf("%s/128", v6addr.String())),
		Description:     aws.String(staticReservationDescription),
		ReservationType: aws.String("explicit"),
		SubnetId:        aws.String(alloc.subnet),
	})
	if err != nil {
		return fmt.Errorf("Cannot make reservation for IPv6 addr: %w", err)
	}

	v4output, err := session.CreateSubnetCidrReservation(ctx, ec2.CreateSubnetCidrReservationInput{
		Cidr:            aws.String(fmt.Sprintf("%s/32", v4addr.String())),
		Description:     aws.String(staticReservationDescription),
		ReservationType: aws.String("explicit"),
		SubnetId:        aws.String(alloc.subnet),
	})
	if err != nil {
		return fmt.Errorf("Cannot make reservation for IPv4 addr: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO subnet_cidr_reservations_v6(reservation_id, subnet_id, prefix, type, description) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING ",
		aws.StringValue(v6output.SubnetCidrReservation.SubnetCidrReservationId),
		alloc.subnet,
		aws.StringValue(v6output.SubnetCidrReservation.Cidr),
		aws.StringValue(v6output.SubnetCidrReservation.ReservationType),
		aws.StringValue(v6output.SubnetCidrReservation.Description),
	)
	if err != nil {
		return fmt.Errorf("Could not insert subnet CIDR v6 reservation %s: %w", aws.StringValue(v6output.SubnetCidrReservation.SubnetCidrReservationId), err)
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO subnet_cidr_reservations_v4(reservation_id, subnet_id, prefix, type, description) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING ",
		aws.StringValue(v4output.SubnetCidrReservation.SubnetCidrReservationId),
		alloc.subnet,
		aws.StringValue(v4output.SubnetCidrReservation.Cidr),
		aws.StringValue(v4output.SubnetCidrReservation.ReservationType),
		aws.StringValue(v4output.SubnetCidrReservation.Description),
	)
	if err != nil {
		return fmt.Errorf("Could not insert subnet CIDR v4 reservation %s: %w", aws.StringValue(v4output.SubnetCidrReservation.SubnetCidrReservationId), err)
	}

	_, err = tx.ExecContext(ctx,
		"UPDATE ip_addresses SET v4prefix = $1, v6prefix = $2 WHERE id = $3",
		aws.StringValue(v4output.SubnetCidrReservation.SubnetCidrReservationId),
		aws.StringValue(v6output.SubnetCidrReservation.SubnetCidrReservationId),
		alloc.id,
	)

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Could not commit transaction: %w")
	}

	return nil
}
