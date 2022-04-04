package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"

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

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	// The dummy interface is used for IP addresses that are allocated
	staticDummyInterfaceDescription = "titus-static-dummy"
	staticReservationDescription    = "titus-static-address"
)

var (
	errAllocationNotFound = status.Error(codes.NotFound, "Could not find allocation")
)

func getDummyStaticInterface(ctx context.Context, session *ec2wrapper.EC2Session, subnetID string) (*ec2.NetworkInterface, error) {
	ctx, span := trace.StartSpan(ctx, "getDummyStaticInterface")
	defer span.End()

	createNetworkInterfaceInput := ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(staticDummyInterfaceDescription),
		SubnetId:         aws.String(subnetID),
		Ipv6AddressCount: aws.Int64(1),
	}

	createNetworkInterfaceOutput, err := session.CreateNetworkInterface(ctx, createNetworkInterfaceInput)
	if err != nil {
		err = fmt.Errorf("Cannot create dummy static network interface: %w", err)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return createNetworkInterfaceOutput.NetworkInterface, nil
}

func allocateStaticSubnetCidrReservations(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, v4addr net.IP, v6addr net.IP, alloc allocation) error {
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
		alloc.subnetID,
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
		alloc.subnetID,
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
	if err != nil {
		return fmt.Errorf("Could not update prefixes: %w", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Could not commit transaction: %w", err)
	}

	return nil
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

	var alloc allocation
	alloc.id = rq.AddressAllocation.Uuid
	if alloc.id == "" {
		alloc.id = uuid.New().String()
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

	_, err = tx.ExecContext(ctx, "INSERT INTO ip_addresses (id) VALUES ($1)", alloc.id)
	if err != nil {
		err = errors.Wrapf(err, "Cannot insert allocation record for UUID %s", alloc.id)
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	row := tx.QueryRowContext(ctx, "SELECT id, az, vpc_id, account_id FROM subnets WHERE subnet_id = $1", rq.AddressAllocation.AddressLocation.SubnetId)
	err = row.Scan(&alloc.subnetID, &alloc.az, &alloc.vpc, &alloc.account)
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

	region := azToRegionRegexp.FindString(alloc.az)
	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		Region:    region,
		AccountID: alloc.account,
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	iface, err := getDummyStaticInterface(ctx, session, rq.AddressAllocation.AddressLocation.SubnetId)
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	ipv4Address := net.ParseIP(*iface.PrivateIpAddress)
	ipv6Address := net.ParseIP(*iface.Ipv6Addresses[0].Ipv6Address)

	err = allocateStaticSubnetCidrReservations(ctx, tx, session, ipv4Address, ipv6Address, alloc)
	if err != nil {
		return nil, errors.Wrap(err, "Could not allocate static subnet cidr reservations")
	}

	allocation := &titus.AddressAllocation{
		AddressLocation: &titus.AddressLocation{
			Region:           region,
			AvailabilityZone: alloc.az,
			SubnetId:         aws.StringValue(iface.SubnetId),
		},
		Uuid:        alloc.id,
		Address:     ipv4Address.String(),
		Ipv6Address: ipv6Address.String(),
	}

	bytes, err := proto.Marshal(allocation)
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
                        home_eni = $6,
                        host_public_key = $7,
                        host_public_key_signature = $8,
                        message = $9,
                        message_signature = $10,
                        account = $11,
						subnet_id_id = $12,
						ipv6address = $13
WHERE id = $1`,
		alloc.id,
		alloc.az,
		region,
		aws.StringValue(iface.SubnetId),
		ipv4Address,
		aws.StringValue(iface.NetworkInterfaceId),
		vpcService.hostPublicKey,
		vpcService.hostPublicKeySignature,
		bytes,
		signature,
		alloc.account,
		alloc.subnetID,
		ipv6Address,
	)
	if err != nil {
		return nil, errors.Wrap(err, "Could not persist allocation")
	}
	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "Could not commit transaction")
	}

	_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: aws.String(*iface.NetworkInterfaceId)})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not delete titus static dummy interface")
	}

	resp := &titus.AllocateAddressResponse{
		SignedAddressAllocation: &titus.SignedAddressAllocation{
			AddressAllocation:      allocation,
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
		rows, err = tx.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address, ipv6address, host_public_key, host_public_key_signature, message, message_signature FROM ip_addresses WHERE ip_address = $1", v.Address)

	case *titus.GetAllocationRequest_Uuid:
		rows, err = tx.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address, ipv6address, host_public_key, host_public_key_signature, message, message_signature FROM ip_addresses WHERE id = $1", v.Uuid)

	case *titus.GetAllocationRequest_Ipv6Address:
		rows, err = tx.QueryContext(ctx, "SELECT id, az, region, subnet_id, ip_address, ipv6address, host_public_key, host_public_key_signature, message, message_signature FROM ip_addresses WHERE id = $1", v.Ipv6Address)

	}
	if err != nil {
		return nil, errors.Wrap(err, "Could not run SQL query")
	}

	if !rows.Next() {
		return nil, errAllocationNotFound
	}
	var id, az, region, subnetid, ipv4address, ipv6address string
	var hostPublicKey, hostPublicKeySignature, message, messageSignature []byte
	err = rows.Scan(&id, &az, &region, &subnetid, &ipv4address, &ipv6address, &hostPublicKey, &hostPublicKeySignature, &message, &messageSignature)
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
		Uuid:        id,
		Address:     ipv4address,
		Ipv6Address: ipv6address,
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
	id       string
	region   string
	account  string
	subnet   string
	vpc      string
	az       string
	subnetID int
}

func FixOldAllocations(ctx context.Context, db *sql.DB, ec2 *ec2wrapper.EC2SessionManager) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	tx, err := db.BeginTx(ctx, &sql.TxOptions{
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
       ip_addresses.id, ip_addresses.region, subnets.id, subnets.account_id, ip_addresses.subnet_id
FROM ip_addresses
JOIN subnets ON ip_addresses.subnet_id = subnets.subnet_id
WHERE ipv6address IS NULL`)
	if err != nil {
		return fmt.Errorf("Could not query IDs from ip_addresses: %w", err)
	}

	var allocations []allocation
	for rows.Next() {
		var alloc allocation
		err = rows.Scan(&alloc.id, &alloc.region, &alloc.subnetID, &alloc.account, &alloc.subnet)
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
		err = fixAllocation(ctx, db, ec2, alloc)
		if err != nil {
			return fmt.Errorf("Could not fix allocation %s: %w", alloc.id, err)
		}
	}

	return nil
}

func fixAllocation(ctx context.Context, db *sql.DB, sessionMgr *ec2wrapper.EC2SessionManager, alloc allocation) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	session, err := sessionMgr.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		AccountID: alloc.account,
		Region:    alloc.region,
	})
	if err != nil {
		return fmt.Errorf("Cannot get session: %w", err)
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return errors.Wrap(err, "Could not start database transaction")
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var ipv4addr string
	var ipv6addr sql.NullString
	var staticInterfaceID string
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
	if !ipv6addr.Valid {
		iface, err := getDummyStaticInterface(ctx, session, alloc.subnet)
		if err != nil {
			return err
		}

		staticInterfaceID = aws.StringValue(iface.NetworkInterfaceId)
		v6addrEni := iface.Ipv6Addresses[0]
		v6addr = net.ParseIP(aws.StringValue(v6addrEni.Ipv6Address))

		_, err = tx.ExecContext(ctx, "UPDATE ip_addresses SET ipv6address = $1 WHERE id = $2", v6addr.String(), alloc.id)
		if err != nil {
			return fmt.Errorf("Could not update ipv6addr: %w", err)
		}
	}

	err = allocateStaticSubnetCidrReservations(ctx, tx, session, v4addr, v6addr, alloc)
	if err != nil {
		return fmt.Errorf("Could not allocate static subnet cidr reservations: %w", err)
	}

	// TODO : delete interface post migration
	if staticInterfaceID != "" {
		_, err = session.DeleteNetworkInterface(ctx, ec2.DeleteNetworkInterfaceInput{NetworkInterfaceId: aws.String(staticInterfaceID)})
		if err != nil {
			logger.G(ctx).WithError(err).Error("Could not delete titus static dummy interface")
		}
	}

	return nil
}
