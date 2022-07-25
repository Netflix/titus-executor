package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/hashicorp/go-multierror"
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
	inUse      = "in-use"
	available  = "available"
	associated = "associated"
)

// getAllRegionAccounts gets regions accounts of the trunk ENI ("accounts"), as well as the
// branch ENI accounts
func (vpcService *vpcService) getAllRegionAccounts(ctx context.Context) ([]data.KeyedItem, error) {
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not start database transaction")
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	rows, err := tx.QueryContext(ctx, "SELECT region, account_id FROM accounts")
	if err != nil {
		return nil, fmt.Errorf("Could not query accounts table: %w", err)
	}

	ret := []data.KeyedItem{}
	for rows.Next() {
		var ra regionAccount
		err = rows.Scan(&ra.region, &ra.accountID)
		if err != nil {
			return nil, fmt.Errorf("Could not 'scan' data from accounts query: %w", err)
		}
		ret = append(ret, &ra)
	}

	rows, err = tx.QueryContext(ctx, "SELECT DISTINCT region, account_id FROM trunk_enis")
	if err != nil {
		return nil, fmt.Errorf("Could not query trunk_enis table: %w", err)
	}
	for rows.Next() {
		var ra regionAccount
		err = rows.Scan(&ra.region, &ra.accountID)
		if err != nil {
			return nil, fmt.Errorf("Could not 'scan' data from trunk_enis query: %w", err)
		}
		ret = append(ret, &ra)
	}

	_ = tx.Commit()
	return ret, nil
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
		"taskIds":  req.RunningTaskIDs,
	})

	resp, err := vpcService.doGCV3(ctx, req)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Failed to get assignments to GC")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	return resp, nil
}

func (vpcService *vpcService) doGCV3(ctx context.Context, req *vpcapi.GCRequestV3) (*vpcapi.GCResponseV3, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "doGCV3")
	defer span.End()

	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
	)

	_, _, trunkENI, err := vpcService.getSessionAndTrunkInterface(ctx, req.InstanceIdentity)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	logger.G(ctx).WithField("taskIds", req.RunningTaskIDs).Debug("GCing for running task IDs")
	resp := vpcapi.GCResponseV3{}

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rowsAffected, err := tx.ExecContext(ctx, `
WITH unused_assignments AS
  (SELECT assignments.id
   FROM branch_eni_attachments
   JOIN assignments ON branch_eni_attachments.association_id = assignments.branch_eni_association
   WHERE trunk_eni = $1
     AND assignments.assignment_id NOT IN
       (SELECT unnest($2::text[]))
     AND assignments.created_at < now() - INTERVAL '5 minutes'
     AND NOT assignments.is_transition_assignment
     AND assignments.gc_tombstone IS NULL)
UPDATE assignments
SET gc_tombstone = now()
FROM unused_assignments
WHERE assignments.id = unused_assignments.id
`, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(req.RunningTaskIDs))
	if err != nil {
		err = fmt.Errorf("Could not tombstone VPC entries: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	n, err := rowsAffected.RowsAffected()
	if err != nil {
		err = fmt.Errorf("Could not find rows affected: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	span.AddAttributes(trace.Int64Attribute("rowsTombstoned", n))

	rows, err := tx.QueryContext(ctx, `
SELECT assignment_id
FROM branch_eni_attachments
JOIN assignments ON branch_eni_attachments.association_id = assignments.branch_eni_association
WHERE trunk_eni = $1
AND assignments.assignment_id NOT IN (SELECT unnest($2::text[]))
AND gc_tombstone < now() - INTERVAL '30 minutes'
`, aws.StringValue(trunkENI.NetworkInterfaceId), pq.Array(req.RunningTaskIDs))
	if err != nil {
		err = errors.Wrap(err, "Could not fetch assignments")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var assignmentID string
		err = rows.Scan(&assignmentID)
		if err != nil {
			err = errors.Wrap(err, "Could not scan assignment ID")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		resp.AssignmentsToRemove = append(resp.AssignmentsToRemove, assignmentID)
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	span.AddAttributes(trace.StringAttribute("assignmentsToRemove", fmt.Sprint(resp.AssignmentsToRemove)))
	logger.G(ctx).WithField("assignmentsToRemove", resp.AssignmentsToRemove).Debug("Fetched assignments to remove")

	return &resp, err
}

// This function, once invoked, is meant to run forever until context is cancelled
// Make this adjustable so it's not done every minute?
func (vpcService *vpcService) doGCAttachedENIsLoop(ctx context.Context, protoItem data.KeyedItem) error {
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
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()

	defer time.AfterFunc(11*time.Minute, func() {
		// TODO: Consider panicing if we hit this condition
		// TODO: Consider adding such a watchdog to all of these functions
		logger.G(ctx).Warning("Function running too long")
	}).Stop()

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
	logger.G(ctx).Info("Beginning GC of ENIs")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: item.accountID, Region: item.region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		tracehelpers.SetStatus(err, span)
		return err
	}

	group, ctx := errgroup.WithContext(ctx)
	eniWQ := make(chan string, 10000)
	describeWQ := make(chan []string, 100)
	gcWQ := make(chan *ec2.NetworkInterface, 10000)
	group.Go(func() error {
		return vpcService.getGCableENIs(ctx, item.region, item.accountID, eniWQ)
	})

	group.Go(func() error {
		return vpcService.describeENIsFoGCWorker(ctx, session, describeWQ, gcWQ)
	})

	group.Go(func() error {
		return vpcService.describeCollector(ctx, eniWQ, describeWQ)
	})

	for i := 0; i < gcWorkers; i++ {
		group.Go(func() error {
			vpcService.gcWorker(ctx, session, gcWQ)
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
		tracehelpers.SetStatus(err, span)
		return err
	}
	rows, err := tx.QueryContext(ctx, `
WITH attached_enis AS
  (SELECT branch_eni,
          trunk_eni
   FROM branch_eni_attachments
   WHERE state = 'attaching'
     OR state = 'attached'
     OR state = 'unattaching')
SELECT branch_enis.branch_eni
FROM branch_enis
JOIN subnets ON branch_enis.subnet_id = subnets.subnet_id
JOIN availability_zones ON subnets.account_id = availability_zones.account_id
AND subnets.az = availability_zones.zone_name
WHERE (branch_enis.branch_eni NOT IN
         (SELECT branch_eni
          FROM attached_enis)
       OR
         (SELECT generation
          FROM trunk_enis
          WHERE trunk_eni =
              (SELECT trunk_eni
               FROM attached_enis
               WHERE branch_eni = branch_enis.branch_eni)) = 3)
  AND branch_enis.account_id = $1
  AND availability_zones.region = $2
ORDER BY RANDOM()
  `, accountID, region)
	if err != nil {
		err = errors.Wrap(err, "Could not start database query to enumerate attached ENIs")
		tracehelpers.SetStatus(err, span)
		return err
	}

	for rows.Next() {
		var eni string
		err = rows.Scan(&eni)
		if err != nil {
			err = errors.Wrap(err, "Could scan eni ID")
			tracehelpers.SetStatus(err, span)
			return err
		}
		select {
		case ch <- eni:
		case <-ctx.Done():
			err = fmt.Errorf("Context done while trying to write to gc-able ENIs: %w", ctx.Err())
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit db txn")
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) describeCollector(ctx context.Context, eniWQ chan string, describeWQ chan []string) error {
	defer close(describeWQ)
	enis := []string{}
	for {
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "Context error while waiting on eniWQ")
		case eni, ok := <-eniWQ:
			if !ok {
				// The queue is complete
				if len(enis) > 0 {
					select {
					case describeWQ <- enis:
					case <-ctx.Done():
						return errors.Wrap(ctx.Err(), "Context error while waiting on describeWQ on final aggregation")
					}
				}
				return nil
			}
			enis = append(enis, eni)
		}
		if len(enis) > gcBatchSize {
			select {
			case describeWQ <- enis:
			case <-ctx.Done():
				return errors.Wrap(ctx.Err(), "Context error while waiting on describeWQ in incremental aggregation")
			}
			enis = []string{}
		}
	}
}

func (vpcService *vpcService) describeENIsFoGCWorker(ctx context.Context, session *ec2wrapper.EC2Session, describeWQ chan []string, gcWQ chan *ec2.NetworkInterface) error {
	defer close(gcWQ)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case describeRQ, ok := <-describeWQ:
			if !ok {
				return nil
			}
			err := vpcService.describeENIsFoGC(ctx, session, describeRQ, gcWQ)
			if err != nil {
				return err
			}
		}
	}
}

func (vpcService *vpcService) describeENIsFoGC(ctx context.Context, session *ec2wrapper.EC2Session, eniList []string, gcWQ chan *ec2.NetworkInterface) error {
	ctx, span := trace.StartSpan(ctx, "describer")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("enis", fmt.Sprint(eniList)),
		trace.Int64Attribute("n", int64(len(eniList))))

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: aws.StringSlice(eniList),
	}

	for {
		describeNetworkInterfacesOutput, err := session.DescribeNetworkInterfaces(ctx, describeNetworkInterfacesInput)
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

func (vpcService *vpcService) gcWorker(ctx context.Context, session *ec2wrapper.EC2Session, wq chan *ec2.NetworkInterface) {
	for {
		select {
		case <-ctx.Done():
			return
		case eni, ok := <-wq:
			if !ok {
				return
			}
			if err := vpcService.doGCENI(ctx, session, eni, vpcService.dbRateLimiter); err != nil {
				logger.G(ctx).WithError(err).Error("Cannot GC ENI")
			}
		}
	}
}

func (vpcService *vpcService) doGCUnattachedENI(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, interfaceIPv4Addresses, interfaceIPv6Addresses sets.String) error {
	ctx, span := trace.StartSpan(ctx, "doGCUnattachedENI")
	defer span.End()

	// This verifies that the branch ENI is not attached when we do the operation
	// Unfortunately, Postgresql doesn't support predicate locking (without SSI mode)
	sqlResult, err := tx.ExecContext(ctx, `
SELECT
FROM branch_enis
WHERE branch_eni = $1 
	AND branch_eni NOT IN (SELECT branch_eni FROM branch_eni_attachments WHERE state = 'attaching' OR state = 'attached' OR state = 'unattaching')
FOR NO KEY UPDATE OF branch_enis
`, aws.StringValue(iface.NetworkInterfaceId))

	if err != nil {
		err = errors.Wrap(err, "Cannot query branch ENI")
		tracehelpers.SetStatus(err, span)
		return err
	}

	n, err := sqlResult.RowsAffected()
	if err != nil {
		err = errors.Wrap(err, "Cannot get rows affected")
		tracehelpers.SetStatus(err, span)
		return err
	}

	if n == 0 {
		err = fmt.Errorf("ENI %q was not found in unattached ENIs", aws.StringValue(iface.NetworkInterfaceId))
		tracehelpers.SetStatus(err, span)
		return err
	}

	group := vpcerrors.NewErrGroupIsh()
	var result *multierror.Error
	removedStaticAddresses, err := removeStaticAddresses(ctx, tx, session, iface, interfaceIPv4Addresses, group)
	if err != nil {
		err = errors.Wrap(err, "Cannot remove static addresses")
		tracehelpers.SetStatus(err, span)
		return err
	}

	for idx := range iface.PrivateIpAddresses {
		ip := iface.PrivateIpAddresses[idx]
		if aws.BoolValue(ip.Primary) && ip.Association != nil {
			association := ip.Association
			group.Run(func() error {
				return removeAssociation(ctx, session, association)
			})
		}
	}

	interfaceIPv4Addresses = interfaceIPv4Addresses.Difference(removedStaticAddresses)
	if interfaceIPv4Addresses.Len() > 0 {
		result = multierror.Append(result, removeIPv4Addresses(ctx, tx, session, iface, interfaceIPv4Addresses.UnsortedList(), group))
	}

	span.AddAttributes(
		trace.StringAttribute("interfaceIPv6Addresses", fmt.Sprintf("%v", interfaceIPv6Addresses.List())),
	)
	if interfaceIPv6Addresses.Len() > 0 {
		result = multierror.Append(result, removeIPv6Addresses(ctx, tx, session, iface, interfaceIPv6Addresses.UnsortedList(), group))
	}

	return multierror.Append(result, group.Wait(ctx)).ErrorOrNil()
}

func (vpcService *vpcService) doGCAttachedENI(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, interfaceIPv4Addresses, interfaceIPv6Addresses sets.String) error {
	ctx, span := trace.StartSpan(ctx, "doGCAttachedENI")
	defer span.End()

	// This verifies that the branch ENI is still attached when we do the operation
	row := tx.QueryRowContext(ctx, `
SELECT association_id
FROM branch_eni_attachments
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
JOIN trunk_enis ON branch_eni_attachments.trunk_eni = trunk_enis.trunk_eni
WHERE branch_eni_attachments.branch_eni = $1
  AND trunk_enis.generation = 3
  AND branch_eni_attachments.state = 'attached'
  FOR NO KEY
  UPDATE OF branch_enis
`, aws.StringValue(iface.NetworkInterfaceId))
	var associationID string
	err := row.Scan(&associationID)
	if err == sql.ErrNoRows {
		err = fmt.Errorf("ENI %q was not in v3 attachments", aws.StringValue(iface.NetworkInterfaceId))
		tracehelpers.SetStatus(err, span)
		return err
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan row")
		tracehelpers.SetStatus(err, span)
		return err
	}

	group := vpcerrors.NewErrGroupIsh()
	var result *multierror.Error
	removedStaticAddresses, err := removeStaticAddresses(ctx, tx, session, iface, interfaceIPv4Addresses, group)
	if err != nil {
		err = errors.Wrap(err, "Cannot remove static addresses")
		tracehelpers.SetStatus(err, span)
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
			tracehelpers.SetStatus(err, span)
			return err
		}

		for rows.Next() {
			var ipAddress string
			err = rows.Scan(&ipAddress)
			if err != nil {
				err = errors.Wrap(err, "Cannot scan unused IPv4 addresses")
				tracehelpers.SetStatus(err, span)
				return err
			}
			ipv4AddressesToRemove.Insert(ipAddress)
		}

		if len(ipv4AddressesToRemove) > 0 {
			result = multierror.Append(err, removeIPv4Addresses(ctx, tx, session, iface, ipv4AddressesToRemove.UnsortedList(), group))
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
			tracehelpers.SetStatus(err, span)
			return err
		}
		// We have no idea why this association is here.
		if c == 0 {
			association := ip.Association
			group.Run(func() error {
				return removeAssociation(ctx, session, association)
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
			tracehelpers.SetStatus(err, span)
			return err
		}

		ipv6AddressesToRemove := []string{}
		for rows.Next() {
			var ipAddress string
			err = rows.Scan(&ipAddress)
			if err != nil {
				err = errors.Wrap(err, "Cannot scan unused IPv6 addresses")
				tracehelpers.SetStatus(err, span)
				return err
			}
			ipv6AddressesToRemove = append(ipv6AddressesToRemove, ipAddress)
		}

		if len(iface.Ipv6Prefixes) > 0 {
			if len(interfaceIPv6Addresses) == len(ipv6AddressesToRemove) && len(ipv6AddressesToRemove) > 0 {
				// Remove one IP from the removal list
				ipv6AddressesToRemove = ipv6AddressesToRemove[1:]
			}
		}

		if len(ipv6AddressesToRemove) > 0 {
			result = multierror.Append(err, removeIPv6Addresses(ctx, tx, session, iface, ipv6AddressesToRemove, group))
		}
	}

	return multierror.Append(result, group.Wait(ctx)).ErrorOrNil()
}

func removeStaticAddresses(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, interfaceIPv4Addresses sets.String, groupish *vpcerrors.ErrGroupish) (sets.String, error) {
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
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	for rows.Next() {
		var ipAddress, homeENI string
		err = rows.Scan(&ipAddress, &homeENI)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan static (unused) ip address")
			tracehelpers.SetStatus(err, span)
			return nil, err
		}
		removedStaticAddresses.Insert(ipAddress)
		groupish.Run(func() error {
			return relocateIPAddress(ctx, session, iface, ipAddress, homeENI)
		})
	}

	return removedStaticAddresses, nil
}

func (vpcService *vpcService) doGCENI(ctx context.Context, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, limiter *rate.Limiter) error { // nolint: gocyclo
	ctx, span := trace.StartSpan(ctx, "doGCENI")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(iface.NetworkInterfaceId)))

	ctx = logger.WithField(ctx, "eni", aws.StringValue(iface.NetworkInterfaceId))
	err := limiter.Wait(ctx)
	if err != nil {
		err = errors.Wrap(err, "Unable to pass database rate limiter")
		tracehelpers.SetStatus(err, span)
		return err
	}

	// TODO: Probably make this timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		tracehelpers.SetStatus(err, span)
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
		err = vpcService.doGCUnattachedENI(ctx, tx, session, iface, interfaceIPv4Addresses, interfaceIPv6Addresses)
	case inUse:
		err = vpcService.doGCAttachedENI(ctx, tx, session, iface, interfaceIPv4Addresses, interfaceIPv6Addresses)
	case associated:
		logger.G(ctx).WithField("iface", iface.String()).Warning("Interface is associate with trunk ENI which is not associated with instance. Trunk ENI must be reconciled prior to GC")
		err = nil
	default:
		logger.G(ctx).WithField("iface", iface.String()).Warning("Observed unknown ENI status")
		err = fmt.Errorf("AWS returned unknown ENI status: %s", s)
	}

	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	err = tx.Commit()
	tracehelpers.SetStatus(err, span)
	return err
}

func relocateIPAddress(ctx context.Context, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, ipAddress, homeENI string) error {
	ctx, span := trace.StartSpan(ctx, "relocateIPAddress")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("ipAddress", ipAddress))
	logger.G(ctx).WithField("ipAddress", ipAddress).Debug("Relocating IP Address")
	_, err := session.UnassignPrivateIPAddresses(ctx, ec2.UnassignPrivateIpAddressesInput{
		NetworkInterfaceId: iface.NetworkInterfaceId,
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
	})
	if err != nil {
		err = errors.Wrap(err, "Cannot unassign static address")
		logger.G(ctx).WithError(err).Debug("Unassigned address")
		tracehelpers.SetStatus(err, span)
		return err
	}

	_, err = session.AssignPrivateIPAddresses(ctx, ec2.AssignPrivateIpAddressesInput{
		AllowReassignment:  aws.Bool(false),
		NetworkInterfaceId: aws.String(homeENI),
		PrivateIpAddresses: aws.StringSlice([]string{ipAddress}),
	})
	logger.G(ctx).WithError(err).Debug("Relocated address")
	return err
}

func removeAssociation(ctx context.Context, session *ec2wrapper.EC2Session, association *ec2.NetworkInterfaceAssociation) error {
	ctx, span := trace.StartSpan(ctx, "removeAssociation")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("association", aws.StringValue(association.AssociationId)))

	logger.G(ctx).WithField("association", aws.StringValue(association.AssociationId)).Debug("Removing association")
	_, err := session.DisassociateAddress(ctx, ec2.DisassociateAddressInput{
		AssociationId: association.AssociationId,
	})
	logger.G(ctx).WithError(err).Debug("Removed association")
	tracehelpers.SetStatus(err, span)
	return err
}

func removeIPv4Addresses(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, ipv4AddressesToRemove []string, group *vpcerrors.ErrGroupish) error {
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
			tracehelpers.SetStatus(err, span)
			span.End()
			return err
		}
		if ipsAssigned > 0 {
			err := fmt.Errorf("Consistency violation detected, trying to unassign %d assigned IP addresses", ipsAssigned)
			tracehelpers.SetStatus(err, span)
			span.End()
			return err
		}
	}

	group.Run(func() error {
		defer span.End()
		logger.G(ctx).WithField("ipv4AddressesToRemove", ipv4AddressesToRemove).Debug("Removing IPv4 Addresses")
		_, err := session.UnassignPrivateIPAddresses(ctx, ec2.UnassignPrivateIpAddressesInput{
			PrivateIpAddresses: aws.StringSlice(ipv4AddressesToRemove),
			NetworkInterfaceId: iface.NetworkInterfaceId,
		})
		logger.G(ctx).WithError(err).Debug("Removed IPv4 Addresses")
		tracehelpers.SetStatus(err, span)
		return err
	})

	return nil
}

func removeIPv6Addresses(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, iface *ec2.NetworkInterface, ipv6AddressesToRemove []string, group *vpcerrors.ErrGroupish) error {
	ctx, span := trace.StartSpan(ctx, "removeIPv6Addresses")
	span.AddAttributes(trace.StringAttribute("ipv6AddressesToRemove", fmt.Sprint(ipv6AddressesToRemove)))

	if aws.StringValue(iface.Status) == inUse {
		row := tx.QueryRowContext(ctx, `
SELECT count(*) FROM assignments
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE ipv6addr = any($1::inet[])
	AND branch_enis.branch_eni = $2
`, pq.Array(ipv6AddressesToRemove), aws.StringValue(iface.NetworkInterfaceId))
		var ipsAssigned int
		if err := row.Scan(&ipsAssigned); err != nil {
			err = errors.Wrap(err, "Cannot query / scan assigned IPs")
			tracehelpers.SetStatus(err, span)
			span.End()
			return err
		}
		if ipsAssigned > 0 {
			err := fmt.Errorf("Consistency violation detected, trying to unassign %d assigned IP addresses", ipsAssigned)
			tracehelpers.SetStatus(err, span)
			span.End()
			return err
		}
	}

	group.Run(func() error {
		defer span.End()
		logger.G(ctx).WithField("ipv6AddressesToRemove", ipv6AddressesToRemove).Debug("Removing IPv6 Addresses")

		_, err := session.UnassignIpv6Addresses(ctx, ec2.UnassignIpv6AddressesInput{
			Ipv6Addresses:      aws.StringSlice(ipv6AddressesToRemove),
			NetworkInterfaceId: iface.NetworkInterfaceId,
		})
		logger.G(ctx).WithError(err).Debug("Removed IPv6 Addresses")

		if err != nil {
			tracehelpers.SetStatus(err, span)
		}
		return err
	})

	return nil
}
