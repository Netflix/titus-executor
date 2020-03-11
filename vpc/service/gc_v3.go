package service

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	gcBatchSize    = 100
	gcWorkers      = 10
	timeBetweenGCs = time.Minute
)

const (
	inUse     = "in-use"
	available = "available"
)

func (vpcService *vpcService) tryReallocateStaticAssignment(ctx context.Context, req *vpcapi.GCRequestV3, trunkENI *ec2.InstanceNetworkInterface) (bool, error) {
	ctx, span := trace.StartSpan(ctx, "tryReallocateStaticAssignment")
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

	// This only works on IPv4 addresses at the moment. But we only statically allocate IPv4 addresses. So
	// it's okay!
	row := tx.QueryRowContext(ctx, `
SELECT ip_addresses.ip_address,
       ip_addresses.home_eni,
       branch_enis.branch_eni,
       branch_enis.account_id,
       branch_enis.az,
       assignments.assignment_id
FROM assignments
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
JOIN ip_addresses ON assignments.ipv4addr = ip_addresses.ip_address AND branch_enis.subnet_id = ip_addresses.subnet_id
WHERE trunk_eni = $1
AND assignments.assignment_id NOT IN (SELECT unnest($2::text[]))
  FOR
  UPDATE OF branch_enis, ip_addresses
  LIMIT 1
`, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(req.RunningTaskIDs))
	var ipAddress, homeENI, branchENI, accountID, az, assignmentID string
	err = row.Scan(&ipAddress, &homeENI, &branchENI, &accountID, &az, &assignmentID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		err = errors.Wrap(err, "Cannot scan static IP adddresses")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: azToRegionRegexp.FindString(az)})
	if err != nil {
		err = errors.Wrap(err, "Cannot get AWS session")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	_, err = session.UnassignPrivateIPAddresses(ctx, ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(branchENI),
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
	})
	// TODO: If the IP address has already been assigned, it's actually "okay"
	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() != invalidParameterValue && strings.HasSuffix(awsErr.Message(), "Some of the specified addresses are not assigned to interface") {
			return false, ec2wrapper.HandleEC2Error(err, span)
		}
	} else if err != nil {
		return false, ec2wrapper.HandleEC2Error(err, span)
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM assignments WHERE assignment_id = $1", assignmentID)
	if err != nil {
		err = errors.Wrap(err, "Could not delete assignment")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return false, err
	}

	_, err = session.AssignPrivateIPAddresses(ctx, ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId: aws.String(homeENI),
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
	})
	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() != invalidParameterValue {
			return false, ec2wrapper.HandleEC2Error(err, span)
		}
	} else if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to relocate IP address back to home ENI")
	}

	return true, nil
}

func (vpcService *vpcService) reallocateStaticAssignments(ctx context.Context, req *vpcapi.GCRequestV3, trunkENI *ec2.InstanceNetworkInterface) error {
	ctx, span := trace.StartSpan(ctx, "reallocateStaticAssignments")
	defer span.End()

	for {
		reassigned, err := vpcService.tryReallocateStaticAssignment(ctx, req, trunkENI)
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			return err
		}
		if !reassigned {
			return nil
		}
	}
}

func (vpcService *vpcService) GCV3(ctx context.Context, req *vpcapi.GCRequestV3) (*vpcapi.GCResponseV3, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "GCV3")
	defer span.End()

	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"instance": req.InstanceIdentity.InstanceID,
	})
	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID))

	_, _, trunkENI, err := vpcService.getSessionAndTrunkInterface(ctx, req.InstanceIdentity)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = vpcService.reallocateStaticAssignments(ctx, req, trunkENI)
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	logger.G(ctx).WithField("taskIds", req.RunningTaskIDs).Debug("GCing for running task IDs")

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	_, err = tx.ExecContext(ctx, `
INSERT INTO branch_eni_last_used (branch_eni, last_used)
SELECT branch_eni,
       now()
FROM branch_eni_attachments
JOIN assignments ON branch_eni_attachments.association_id = assignments.branch_eni_association
WHERE trunk_eni = $1
  AND assignments.assignment_id NOT IN (SELECT unnest($2::text[]))
GROUP BY branch_eni ON CONFLICT (branch_eni) DO
UPDATE
SET last_used = now()
`, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(req.RunningTaskIDs))
	if err != nil {
		err = errors.Wrap(err, "Could update branch eni last used times")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_, err = tx.ExecContext(ctx, `
WITH unused_ips AS
  (SELECT branch_eni,
          unnest(ARRAY[ipv4addr, ipv6addr]) AS ip_address
   FROM branch_eni_attachments
   JOIN assignments ON branch_eni_attachments.association_id = assignments.branch_eni_association
   WHERE trunk_eni = $1
     AND assignments.assignment_id NOT IN (SELECT unnest($2::text[])))
INSERT INTO ip_last_used_v3(vpc_id, ip_address, last_seen)
SELECT vpc_id,
       ip_address,
       now()
FROM unused_ips
JOIN branch_enis ON unused_ips.branch_eni = branch_enis.branch_eni
WHERE ip_address IS NOT NULL ON CONFLICT (ip_address, vpc_id) DO
  UPDATE
  SET last_seen = now()
`, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(req.RunningTaskIDs))
	if err != nil {
		err = errors.Wrap(err, "Could update ip last used times")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_, err = tx.ExecContext(ctx, `
DELETE
FROM assignments
WHERE assignment_id IN
    (SELECT assignment_id
     FROM branch_eni_attachments
     JOIN assignments ON branch_eni_attachments.association_id = assignments.branch_eni_association
     WHERE trunk_eni = $1
     AND assignments.assignment_id NOT IN (SELECT unnest($2::text[])))
`, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(req.RunningTaskIDs))
	if err != nil {
		err = errors.Wrap(err, "Could not delete assignments")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	_, err = tx.ExecContext(ctx, "UPDATE branch_eni_attachments SET attachment_generation = 3 WHERE trunk_eni = $1", aws.StringValue(trunkENI.NetworkInterfaceId))
	if err != nil {
		err = errors.Wrap(err, "Could not update attachment generations")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Unable to commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}

	return &vpcapi.GCResponseV3{}, nil

}

// This function, once invoked, is meant to run forever until context is cancelled
// Make this adjustable so it's not done every minute?
func (vpcService *vpcService) doGCAttachedENIsLoop(ctx context.Context, protoItem keyedItem) error {
	item := protoItem.(*regionAccount)
	for {
		err := vpcService.doGCENIs(ctx, item)
		if err != nil {
			logger.G(ctx).WithField("region", item.region).WithField("accountID", item.accountID).WithError(err).Error("Failed to adequately GC interfaces")
		}
		err = waitFor(ctx, timeBetweenGCs)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doGCENIs(ctx context.Context, item *regionAccount) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doGCENIs")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("region", item.region),
		trace.StringAttribute("accountID", item.accountID),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"region":    item.region,
		"accountID": item.accountID,
	})
	logger.G(ctx).Debug("Beginning GC of ENIs")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: item.accountID, Region: item.region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	ec2client := ec2.New(session.Session)
	group, ctx := errgroup.WithContext(ctx)
	eniWQ := make(chan string, 10000)
	describeWQ := make(chan []string, 100)
	gcWQ := make(chan *ec2.NetworkInterface, 10000)
	group.Go(func() error {
		return vpcService.getGCableENIs(ctx, item.region, item.accountID, eniWQ)
	})

	group.Go(func() error {
		return vpcService.describeENIsFoGCWorker(ctx, ec2client, describeWQ, gcWQ)
	})

	group.Go(func() error {
		vpcService.describeCollector(ctx, eniWQ, describeWQ)
		return nil
	})

	for i := 0; i < gcWorkers; i++ {
		group.Go(func() error {
			vpcService.gcWorker(ctx, ec2client, gcWQ)
			return nil
		})
	}

	return group.Wait()
}

func (vpcService *vpcService) getGCableENIs(ctx context.Context, region, accountID string, ch chan string) error {
	ctx, span := trace.StartSpan(ctx, "getGCableENIs")
	defer span.End()

	defer close(ch)

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	defer func() {
		_ = tx.Rollback()
	}()

	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction to enumerate ENIs")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	rows, err := tx.QueryContext(ctx, `
SELECT branch_enis.branch_eni
FROM branch_enis
JOIN subnets ON branch_enis.subnet_id = subnets.subnet_id
JOIN availability_zones ON subnets.account_id = availability_zones.account_id AND subnets.az = availability_zones.zone_name
LEFT JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
WHERE (attachment_generation = 3 OR branch_eni_attachments.association_id IS NULL)
  AND branch_enis.account_id = $1
  AND availability_zones.region = $2
ORDER BY RANDOM()
  `, accountID, region)
	if err != nil {
		err = errors.Wrap(err, "Could not start database query to enumerate attached ENIs")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	for rows.Next() {
		var eni string
		err = rows.Scan(&eni)
		if err != nil {
			err = errors.Wrap(err, "Could scan eni ID")
			span.SetStatus(traceStatusFromError(err))
			return err
		}
		ch <- eni
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit db txn")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}

func (vpcService *vpcService) describeCollector(ctx context.Context, eniWQ chan string, describeWQ chan []string) {
	defer close(describeWQ)
	enis := []string{}
	for {
		select {
		case <-ctx.Done():
			return
		case eni, ok := <-eniWQ:
			if !ok {
				// The queue is complete
				if len(enis) > 0 {
					describeWQ <- enis
				}
				return
			}
			enis = append(enis, eni)
		}
		if len(enis) > gcBatchSize {
			describeWQ <- enis
			enis = []string{}
		}
	}
}

func (vpcService *vpcService) describeENIsFoGCWorker(ctx context.Context, ec2client *ec2.EC2, describeWQ chan []string, gcWQ chan *ec2.NetworkInterface) error {
	defer close(gcWQ)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case describeRQ, ok := <-describeWQ:
			if !ok {
				return nil
			}
			err := vpcService.describeENIsFoGC(ctx, ec2client, describeRQ, gcWQ)
			if err != nil {
				return err
			}
		}
	}
}

func (vpcService *vpcService) describeENIsFoGC(ctx context.Context, ec2client *ec2.EC2, eniList []string, gcWQ chan *ec2.NetworkInterface) error {
	ctx, span := trace.StartSpan(ctx, "describer")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("enis", fmt.Sprint(eniList)),
		trace.Int64Attribute("n", int64(len(eniList))))

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: aws.StringSlice(eniList),
	}

	for {
		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &describeNetworkInterfacesInput)
		if err != nil {
			err = errors.Wrap(err, "Cannot describe ENIs")
			return err
		}
		for idx := range describeNetworkInterfacesOutput.NetworkInterfaces {
			i := describeNetworkInterfacesOutput.NetworkInterfaces[idx]
			select {
			case <-ctx.Done():
				return ctx.Err()
			case gcWQ <- i:
			}
		}
		if describeNetworkInterfacesOutput.NextToken == nil {
			return nil
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}

}

func (vpcService *vpcService) gcWorker(ctx context.Context, ec2client *ec2.EC2, wq chan *ec2.NetworkInterface) {
	for {
		select {
		case <-ctx.Done():
			return
		case eni, ok := <-wq:
			if !ok {
				return
			}
			if err := vpcService.doGCENI(ctx, ec2client, eni, vpcService.dbRateLimiter); err != nil {
				logger.G(ctx).WithError(err).Error("Cannot GC ENI")
			}
		}
	}
}

func (vpcService *vpcService) doGCUnattachedENI(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, iface *ec2.NetworkInterface, interfaceIPv4Addresses, interfaceIPv6Addresses sets.String) error {
	ctx, span := trace.StartSpan(ctx, "doGCUnattachedENI")
	defer span.End()

	// This verifies that the branch ENI is not attached when we do the operation
	// Unfortunately, Postgresql doesn't support predicate locking (without SSI mode)
	row := tx.QueryRowContext(ctx, `
SELECT 1
FROM branch_enis
WHERE branch_eni = $1 
	AND branch_eni NOT IN (SELECT branch_eni FROM branch_eni_attachments)
FOR UPDATE
`, aws.StringValue(iface.NetworkInterfaceId))
	var associationID string
	err := row.Scan(&associationID)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("ENI %q was not found in unattached ENIs", aws.StringValue(iface.NetworkInterfaceId))
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan row")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	group := newErrGroupIsh()
	var result *multierror.Error
	removedStaticAddresses, err := removeStaticAddresses(ctx, tx, ec2client, iface, interfaceIPv4Addresses, group)
	if err != nil {
		err = errors.Wrap(err, "Cannot remove static addresses")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	for idx := range iface.PrivateIpAddresses {
		ip := iface.PrivateIpAddresses[idx]
		if aws.BoolValue(ip.Primary) && ip.Association != nil {
			association := ip.Association
			group.run(func() error {
				return removeAssociation(ctx, ec2client, association)
			})
		}
	}

	interfaceIPv4Addresses = interfaceIPv4Addresses.Difference(removedStaticAddresses)
	if interfaceIPv4Addresses.Len() > 0 {
		result = multierror.Append(result, removeIPv4Addresses(ctx, tx, ec2client, iface, interfaceIPv4Addresses.UnsortedList(), group))
	}

	if interfaceIPv6Addresses.Len() > 0 {
		result = multierror.Append(result, removeIPv6Addresses(ctx, tx, ec2client, iface, interfaceIPv6Addresses.UnsortedList(), group))
	}

	return multierror.Append(result, group.wait(ctx)).ErrorOrNil()
}

func (vpcService *vpcService) doGCAttachedENI(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, iface *ec2.NetworkInterface, interfaceIPv4Addresses, interfaceIPv6Addresses sets.String) error {
	ctx, span := trace.StartSpan(ctx, "doGCAttachedENI")
	defer span.End()

	// This verifies that the branch ENI is still attached when we do the operation
	row := tx.QueryRowContext(ctx, `
SELECT association_id
FROM branch_eni_attachments
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE branch_eni_attachments.branch_eni = $1
  AND attachment_generation = 3
  FOR
  UPDATE OF branch_enis
`, aws.StringValue(iface.NetworkInterfaceId))
	var associationID string
	err := row.Scan(&associationID)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("ENI %q was not in v3 attachments", aws.StringValue(iface.NetworkInterfaceId))
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan row")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	group := newErrGroupIsh()
	var result *multierror.Error
	removedStaticAddresses, err := removeStaticAddresses(ctx, tx, ec2client, iface, interfaceIPv4Addresses, group)
	if err != nil {
		err = errors.Wrap(err, "Cannot remove static addresses")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	interfaceIPv4Addresses = interfaceIPv4Addresses.Difference(removedStaticAddresses)
	ipv4AddressesToRemove := sets.NewString()
	if interfaceIPv4Addresses.Len() > 0 {
		rows, err := tx.QueryContext(ctx, `
WITH interface_v4_addresses AS
  (SELECT unnest($1::text[])::INET AS ip_address,
          $2 AS assoc_id,
          $3 AS vpc_id),
     unassigned_ip_addresses AS
  (SELECT interface_v4_addresses.ip_address,
          vpc_id
   FROM interface_v4_addresses
   LEFT JOIN assignments ON interface_v4_addresses.ip_address = assignments.ipv4addr AND interface_v4_addresses.assoc_id = assignments.branch_eni_association
   WHERE assignment_id IS NULL ),
     unassigned_ip_addresses_with_last_seen AS
  (SELECT unassigned_ip_addresses.ip_address,
          last_seen
   FROM unassigned_ip_addresses
   LEFT JOIN ip_last_used_v3 ON unassigned_ip_addresses.ip_address = ip_last_used_v3.ip_address AND unassigned_ip_addresses.vpc_id = ip_last_used_v3.vpc_id)
SELECT ip_address
FROM unassigned_ip_addresses_with_last_seen
WHERE last_seen < now() - INTERVAL '2 minutes' OR last_seen IS NULL
`, pq.Array(interfaceIPv4Addresses.UnsortedList()), associationID, aws.StringValue(iface.VpcId))
		if err != nil {
			err = errors.Wrap(err, "Cannot query for unused IPv4 addresses")
			span.SetStatus(traceStatusFromError(err))
			return err
		}

		for rows.Next() {
			var ipAddress string
			err = rows.Scan(&ipAddress)
			if err != nil {
				err = errors.Wrap(err, "Cannot scan unused IPv4 addresses")
				span.SetStatus(traceStatusFromError(err))
				return err
			}
			ipv4AddressesToRemove.Insert(ipAddress)
		}

		if len(ipv4AddressesToRemove) > 0 {
			result = multierror.Append(err, removeIPv4Addresses(ctx, tx, ec2client, iface, ipv4AddressesToRemove.UnsortedList(), group))
		}
	}

	for _, ip := range iface.PrivateIpAddresses {
		if removedStaticAddresses.Has(aws.StringValue(ip.PrivateIpAddress)) {
			continue
		}
		if ipv4AddressesToRemove.Has(aws.StringValue(ip.PrivateIpAddress)) {
			continue
		}
		if ip.Association == nil {
			continue
		}
		row := tx.QueryRowContext(ctx, "SELECT count(*) FROM elastic_ip_attachments WHERE association_id = $1", aws.StringValue(ip.Association.AssociationId))
		var c int
		err = row.Scan(&c)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan row")
			span.SetStatus(traceStatusFromError(err))
			return err
		}
		// We have no idea why this association is here.
		if c == 0 {
			association := ip.Association
			group.run(func() error {
				return removeAssociation(ctx, ec2client, association)
			})
		}
	}

	if interfaceIPv6Addresses.Len() > 0 {
		rows, err := tx.QueryContext(ctx, `
WITH interface_v6_addresses AS
  (SELECT unnest($1::text[])::INET AS ip_address,
          $2 AS assoc_id,
          $3 AS vpc_id),
     unassigned_ip_addresses AS
  (SELECT interface_v6_addresses.ip_address,
          vpc_id
   FROM interface_v6_addresses
   LEFT JOIN assignments ON interface_v6_addresses.ip_address = assignments.ipv6addr AND interface_v6_addresses.assoc_id = assignments.branch_eni_association
   WHERE assignment_id IS NULL ),
     unassigned_ip_addresses_with_last_seen AS
  (SELECT unassigned_ip_addresses.ip_address,
          last_seen
   FROM unassigned_ip_addresses
   LEFT JOIN ip_last_used_v3 ON unassigned_ip_addresses.ip_address = ip_last_used_v3.ip_address AND unassigned_ip_addresses.vpc_id = ip_last_used_v3.vpc_id)
SELECT ip_address
FROM unassigned_ip_addresses_with_last_seen
WHERE last_seen < now() - INTERVAL '2 minutes' OR last_seen IS NULL
`, pq.Array(interfaceIPv6Addresses.UnsortedList()), associationID, aws.StringValue(iface.VpcId))
		if err != nil {
			err = errors.Wrap(err, "Cannot query for unused IPv6 addresses")
			span.SetStatus(traceStatusFromError(err))
			return err
		}

		ipv6AddressesToRemove := []string{}
		for rows.Next() {
			var ipAddress string
			err = rows.Scan(&ipAddress)
			if err != nil {
				err = errors.Wrap(err, "Cannot scan unused IPv6 addresses")
				span.SetStatus(traceStatusFromError(err))
				return err
			}
			ipv6AddressesToRemove = append(ipv6AddressesToRemove, ipAddress)
		}

		if len(ipv6AddressesToRemove) > 0 {
			result = multierror.Append(err, removeIPv6Addresses(ctx, tx, ec2client, iface, ipv6AddressesToRemove, group))
		}
	}

	return multierror.Append(result, group.wait(ctx)).ErrorOrNil()
}

func removeStaticAddresses(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, iface *ec2.NetworkInterface, interfaceIPv4Addresses sets.String, groupish *errGroupish) (sets.String, error) {
	removedStaticAddresses := sets.NewString()
	if interfaceIPv4Addresses.Len() == 0 {
		return removedStaticAddresses, nil
	}
	ctx, span := trace.StartSpan(ctx, "removeStaticAddresses")
	defer span.End()

	rows, err := tx.QueryContext(ctx, `
WITH interface_v4_addresses AS
  (SELECT unnest($1::text[])::INET AS ip_address,
          $2 AS vpc_id,
          $3 AS subnet_id),
     unassigned_ip_addresses AS
  (SELECT ip_addresses.ip_address,
          home_eni
   FROM interface_v4_addresses
   JOIN ip_addresses ON interface_v4_addresses.ip_address = ip_addresses.ip_address AND interface_v4_addresses.subnet_id = ip_addresses.subnet_id
   WHERE ip_addresses.id NOT IN (SELECT ip_address_uuid FROM ip_address_attachments) FOR UPDATE OF ip_addresses )
SELECT ip_address,
       home_eni
FROM unassigned_ip_addresses
`, pq.Array(interfaceIPv4Addresses.UnsortedList()), aws.StringValue(iface.VpcId), aws.StringValue(iface.SubnetId))
	if err != nil {
		err = errors.Wrap(err, "Cannot query for unused static IPv4 addresses")
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	for rows.Next() {
		var ipAddress, homeENI string
		err = rows.Scan(&ipAddress, &homeENI)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan static (unused) ip address")
			span.SetStatus(traceStatusFromError(err))
			return nil, err
		}
		removedStaticAddresses.Insert(ipAddress)
		groupish.run(func() error {
			return relocateIPAddress(ctx, ec2client, iface, ipAddress, homeENI)
		})
	}

	return removedStaticAddresses, nil
}

func (vpcService *vpcService) doGCENI(ctx context.Context, ec2client *ec2.EC2, iface *ec2.NetworkInterface, limiter *rate.Limiter) error { // nolint: gocyclo
	ctx, span := trace.StartSpan(ctx, "doGCENI")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(iface.NetworkInterfaceId)))

	ctx = logger.WithField(ctx, "eni", aws.StringValue(iface.NetworkInterfaceId))
	err := limiter.Wait(ctx)
	if err != nil {
		err = errors.Wrap(err, "Unable to pass database rate limiter")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	// TODO: Probably make this timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	interfaceIPv4Addresses := sets.NewString()
	for _, ip := range iface.PrivateIpAddresses {
		if !aws.BoolValue(ip.Primary) {
			interfaceIPv4Addresses.Insert(aws.StringValue(ip.PrivateIpAddress))
		}
	}

	interfaceIPv6Addresses := sets.NewString()
	for _, ip := range iface.Ipv6Addresses {
		interfaceIPv6Addresses.Insert(aws.StringValue(ip.Ipv6Address))
	}

	switch s := aws.StringValue(iface.Status); s {
	case available:
		err = vpcService.doGCUnattachedENI(ctx, tx, ec2client, iface, interfaceIPv4Addresses, interfaceIPv6Addresses)
	case inUse:
		err = vpcService.doGCAttachedENI(ctx, tx, ec2client, iface, interfaceIPv4Addresses, interfaceIPv6Addresses)
	default:
		err = fmt.Errorf("AWS returned unknown ENI status: %s", s)
	}

	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	err = tx.Commit()
	span.SetStatus(traceStatusFromError(err))
	return err
}

func relocateIPAddress(ctx context.Context, ec2client *ec2.EC2, iface *ec2.NetworkInterface, ipAddress, homeENI string) error {
	ctx, span := trace.StartSpan(ctx, "relocateIPAddress")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("ipAddress", ipAddress))
	logger.G(ctx).WithField("ipAddress", ipAddress).Debug("Relocating IP Address")
	_, err := ec2client.UnassignPrivateIpAddressesWithContext(ctx, &ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: iface.NetworkInterfaceId,
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot unassign static address")
		logger.G(ctx).WithError(err).Debug("Unassigned address")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	_, err = ec2client.AssignPrivateIpAddressesWithContext(ctx, &ec2.AssignPrivateIpAddressesInput{
		AllowReassignment:  aws.Bool(false),
		NetworkInterfaceId: aws.String(homeENI),
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
	})
	logger.G(ctx).WithError(err).Debug("Relocated address")
	return err
}

func removeAssociation(ctx context.Context, ec2client *ec2.EC2, association *ec2.NetworkInterfaceAssociation) error {
	ctx, span := trace.StartSpan(ctx, "removeAssociation")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("association", aws.StringValue(association.AssociationId)))

	logger.G(ctx).WithField("association", aws.StringValue(association.AssociationId)).Debug("Removing association")
	_, err := ec2client.DisassociateAddressWithContext(ctx, &ec2.DisassociateAddressInput{
		AssociationId: association.AssociationId,
	})
	logger.G(ctx).WithError(err).Debug("Removed association")
	span.SetStatus(traceStatusFromError(err))
	return err
}

func removeIPv4Addresses(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, iface *ec2.NetworkInterface, ipv4AddressesToRemove []string, group *errGroupish) error {
	ctx, span := trace.StartSpan(ctx, "removeIPv4Addresses")
	span.AddAttributes(trace.StringAttribute("ipv4AddressesToRemove", fmt.Sprint(ipv4AddressesToRemove)))

	if aws.StringValue(iface.Status) == inUse {
		row := tx.QueryRowContext(ctx, `
SELECT count(*) FROM assignments
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE ipv4addr = any($1::inet[])
	AND branch_enis.branch_eni = $2
`, pq.Array(ipv4AddressesToRemove), aws.StringValue(iface.NetworkInterfaceId))
		var ipsAssigned int
		if err := row.Scan(&ipsAssigned); err != nil {
			err = errors.Wrap(err, "Cannot query / scan assigned IPs")
			span.SetStatus(traceStatusFromError(err))
			span.End()
			return err
		}
		if ipsAssigned > 0 {
			err := fmt.Errorf("Consistency violation detected, trying to unassign %d assigned IP addresses", ipsAssigned)
			span.SetStatus(traceStatusFromError(err))
			span.End()
			return err
		}
	}

	group.run(func() error {
		defer span.End()
		logger.G(ctx).WithField("ipv4AddressesToRemove", ipv4AddressesToRemove).Debug("Removing IPv4 Addresses")
		_, err := ec2client.UnassignPrivateIpAddresses(&ec2.UnassignPrivateIpAddressesInput{
			PrivateIpAddresses: aws.StringSlice(ipv4AddressesToRemove),
			NetworkInterfaceId: iface.NetworkInterfaceId,
		})
		logger.G(ctx).WithError(err).Debug("Removed IPv4 Addresses")
		span.SetStatus(traceStatusFromError(err))
		return err
	})

	return nil
}

func removeIPv6Addresses(ctx context.Context, tx *sql.Tx, ec2client *ec2.EC2, iface *ec2.NetworkInterface, ipv6AddressesToRemove []string, group *errGroupish) error {
	ctx, span := trace.StartSpan(ctx, "removeIPv6Addresses")
	span.AddAttributes(trace.StringAttribute("ipv6AddressesToRemove", fmt.Sprint(ipv6AddressesToRemove)))

	if aws.StringValue(iface.Status) == inUse {
		row := tx.QueryRowContext(ctx, `
SELECT count(*) FROM assignments
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE ipv4addr = any($1::inet[])
	AND branch_enis.branch_eni = $2
`, pq.Array(ipv6AddressesToRemove), aws.StringValue(iface.NetworkInterfaceId))
		var ipsAssigned int
		if err := row.Scan(&ipsAssigned); err != nil {
			err = errors.Wrap(err, "Cannot query / scan assigned IPs")
			span.SetStatus(traceStatusFromError(err))
			span.End()
			return err
		}
		if ipsAssigned > 0 {
			err := fmt.Errorf("Consistency violation detected, trying to unassign %d assigned IP addresses", ipsAssigned)
			span.SetStatus(traceStatusFromError(err))
			span.End()
			return err
		}
	}

	group.run(func() error {
		defer span.End()
		logger.G(ctx).WithField("ipv6AddressesToRemove", ipv6AddressesToRemove).Debug("Removing IPv6 Addresses")

		_, err := ec2client.UnassignIpv6Addresses(&ec2.UnassignIpv6AddressesInput{
			Ipv6Addresses:      aws.StringSlice(ipv6AddressesToRemove),
			NetworkInterfaceId: iface.NetworkInterfaceId,
		})
		logger.G(ctx).WithError(err).Debug("Removed IPv6 Addresses")

		if err != nil {
			span.SetStatus(traceStatusFromError(err))
		}
		return err
	})

	return nil
}
