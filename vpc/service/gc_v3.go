package service

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"
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
  UPDATE
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

// We run one attached GC loop per account / region
func (vpcService *vpcService) gcAttachedENIs(ctx context.Context) error {
	startedLockers := sets.NewString()
	hostname, err := os.Hostname()
	if err != nil {
		return errors.Wrap(err, "Cannot get hostname")
	}

	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		err := vpcService.startGCAttachedENIs(ctx, hostname, startedLockers)
		if err != nil {
			return err
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			return nil
		}
	}
}

func (vpcService *vpcService) startGCAttachedENIs(ctx context.Context, hostname string, lockers sets.String) error {
	ctx, span := trace.StartSpan(ctx, "startGCAttachedENIs")
	defer span.End()

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, "SELECT (regexp_match(az, '[a-z]+-[a-z]+-[0-9]+'))[1] AS region, account_id FROM branch_enis GROUP BY region, account_id")
	if err != nil {
		err = errors.Wrap(err, "Cannot run query to fetch all branch ENI region / accounts")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	for rows.Next() {
		var region, accountID string
		err = rows.Scan(&region, &accountID)
		if err != nil {
			err = errors.Wrap(err, "Cannot scan row")
			span.SetStatus(traceStatusFromError(err))
			return err
		}
		taskName := fmt.Sprintf("gc_attach_enis_%s_%s", region, accountID)
		if !lockers.Has(taskName) {
			go vpcService.waitToAcquireLongLivedLock(ctx, hostname, taskName, func(ctx2 context.Context) {
				logger.G(ctx).WithField("taskName", taskName).Debug("Work fun starting")
				vpcService.doGCAttachedENIsLoop(ctx2, region, accountID)
				logger.G(ctx).WithField("taskName", taskName).Debug("Work fun ending")
			})
			lockers.Insert(taskName)
		}
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Cannot commit transaction")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	return nil
}

// This function, once invoked, is meant to run forever until context is cancelled
// Make this adjustable so it's not done every minute?
func (vpcService *vpcService) doGCAttachedENIsLoop(ctx context.Context, region, accountID string) {
	timer := time.NewTimer(time.Minute)
	timer.Stop()
	for {
		err := vpcService.doGCAttachedENIs(ctx, region, accountID)
		if err != nil {
			logger.G(ctx).WithField("region", region).WithField("accountID", accountID).WithError(err).Error("Failed to adequately GC interfaces")
		}
		timer.Reset(time.Minute)
		select {
		case <-timer.C:
		case <-ctx.Done():
			return
		}
	}
}

type concurrencyLimiter struct {
	awsv4ratelimiter     *rate.Limiter
	awsv6ratelimiter     *rate.Limiter
	dbratelimiter        *rate.Limiter
	dbconcurrencylimiter *semaphore.Weighted
}

func (vpcService *vpcService) doGCAttachedENIs(ctx context.Context, region, accountID string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doGCAttachedENIs")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("region", region),
		trace.StringAttribute("accountID", accountID),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"region":    region,
		"accountID": accountID,
	})
	logger.G(ctx).Debug("Beginning GC of ENIs")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: accountID, Region: region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	ec2client := ec2.New(session.Session)

	describeNetworkInterfacesInput := ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("description"),
				Values: aws.StringSlice([]string{vpc.BranchNetworkInterfaceDescription}),
			},
			{
				Name:   aws.String("owner-id"),
				Values: aws.StringSlice([]string{accountID}),
			},
			{
				Name:   aws.String("status"),
				Values: aws.StringSlice([]string{"in-use"}),
			},
		},
		MaxResults: aws.Int64(1000),
	}

	// TODO: Tune all of these constants to sane numbers?
	limiter := &concurrencyLimiter{
		awsv4ratelimiter:     rate.NewLimiter(10, 1),
		awsv6ratelimiter:     rate.NewLimiter(10, 1),
		dbratelimiter:        rate.NewLimiter(100, 1),
		dbconcurrencylimiter: semaphore.NewWeighted(100),
	}

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	group, ctx := errgroup.WithContext(ctx)
	n := 0
	for {
		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &describeNetworkInterfacesInput)
		if err != nil {
			err = errors.Wrap(err, "Cannot not describe network interfaces")
			span.SetStatus(traceStatusFromError(err))
			return err
		}

		networkInterfaces := describeNetworkInterfacesOutput.NetworkInterfaces

		r1.Shuffle(len(networkInterfaces), func(i, j int) {
			networkInterfaces[i], networkInterfaces[j] = networkInterfaces[j], networkInterfaces[i]
		})

		for idx := range describeNetworkInterfacesOutput.NetworkInterfaces {
			// I think this prevents the concurrency problem in for loops?
			iface := describeNetworkInterfacesOutput.NetworkInterfaces[idx]
			group.Go(func() error {
				vpcService.doGCAttachedENI(ctx, ec2client, iface, limiter)
				return nil
			})
			n++
		}

		if describeNetworkInterfacesOutput.NextToken == nil {
			break
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}

	logger.G(ctx).WithField("n", n).Debug("Started all GC workers")
	group.Wait()
	logger.G(ctx).WithField("n", n).Debug("All GC workers finished")
	return nil
}

func (vpcService *vpcService) doGCAttachedENI(ctx context.Context, ec2client *ec2.EC2, iface *ec2.NetworkInterface, limiter *concurrencyLimiter) {
	err := limiter.dbconcurrencylimiter.Acquire(ctx, 1)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to acquire concurrency limiter")
		return
	}
	defer limiter.dbconcurrencylimiter.Release(1)

	err = limiter.dbratelimiter.Wait(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Unable to pass database rate limiter")
		return
	}

	// TODO: Probably make this timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doGCAttachedENI")
	defer span.End()
	ctx = logger.WithField(ctx, "eni", aws.StringValue(iface.NetworkInterfaceId))
	span.AddAttributes(trace.StringAttribute("eni", aws.StringValue(iface.NetworkInterfaceId)))

	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error()
	}

	defer func() {
		_ = tx.Rollback()
	}()

	// This verifies that the branch ENI is still attached when we do the operation
	row := tx.QueryRowContext(ctx, `
SELECT association_id
FROM branch_eni_attachments
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE branch_eni_attachments.branch_eni = $1
  AND attachment_generation = 3
  FOR
  UPDATE
`, aws.StringValue(iface.NetworkInterfaceId))
	var associationID string
	err = row.Scan(&associationID)
	if err == sql.ErrNoRows {
		return
	}

	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error("Cannot scan row")
	}

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

	errCh := make(chan error, 2)
	dispatched := 0

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
          COALESCE(last_seen, TIMESTAMP 'EPOCH') AS last_seen
   FROM unassigned_ip_addresses
   LEFT JOIN ip_last_used_v3 ON unassigned_ip_addresses.ip_address = ip_last_used_v3.ip_address AND unassigned_ip_addresses.vpc_id = ip_last_used_v3.vpc_id)
SELECT ip_address,
       last_seen
FROM unassigned_ip_addresses_with_last_seen
WHERE last_seen < now() - INTERVAL '2 minutes'
`, pq.Array(interfaceIPv4Addresses.UnsortedList()), associationID, aws.StringValue(iface.VpcId))
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			logger.G(ctx).WithError(err).Error("Cannot query for unused IPv4 addresses")
		}

		ipv4AddressesToRemove := []string{}
		for rows.Next() {
			var ipAddress string
			var lastSeen time.Time
			err = rows.Scan(&ipAddress, &lastSeen)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				logger.G(ctx).WithError(err).Error("Cannot scan unused IPv4 addresses")
			}
			ipv4AddressesToRemove = append(ipv4AddressesToRemove, ipAddress)
		}

		if len(ipv4AddressesToRemove) > 0 {
			dispatched++
			go removeIPv4Addresses(ctx, ec2client, iface, ipv4AddressesToRemove, errCh, limiter)
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
          COALESCE(last_seen, TIMESTAMP 'EPOCH') AS last_seen
   FROM unassigned_ip_addresses
   LEFT JOIN ip_last_used_v3 ON unassigned_ip_addresses.ip_address = ip_last_used_v3.ip_address AND unassigned_ip_addresses.vpc_id = ip_last_used_v3.vpc_id)
SELECT ip_address,
       last_seen
FROM unassigned_ip_addresses_with_last_seen
WHERE last_seen < now() - INTERVAL '2 minutes'
`, pq.Array(interfaceIPv6Addresses.UnsortedList()), associationID, aws.StringValue(iface.VpcId))
		if err != nil {
			span.SetStatus(traceStatusFromError(err))
			logger.G(ctx).WithError(err).Error("Cannot query for unused IPv4 addresses")
		}

		ipv6AddressesToRemove := []string{}
		for rows.Next() {
			var ipAddress string
			var lastSeen time.Time
			err = rows.Scan(&ipAddress, &lastSeen)
			if err != nil {
				span.SetStatus(traceStatusFromError(err))
				logger.G(ctx).WithError(err).Error("Cannot scan unused IPv4 addresses")
			}
			ipv6AddressesToRemove = append(ipv6AddressesToRemove, ipAddress)
		}

		if len(ipv6AddressesToRemove) > 0 {
			dispatched++
			go removeIPv6Addresses(ctx, ec2client, iface, ipv6AddressesToRemove, errCh, limiter)
		}
	}

	var result *multierror.Error
	for dispatched > 0 {
		select {
		case err := <-errCh:
			result = multierror.Append(result, err)
			dispatched--
		case <-ctx.Done():
			result = multierror.Append(result, ctx.Err())
			goto out
		}
	}
out:
	err = result.ErrorOrNil()
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		logger.G(ctx).WithError(err).Error("Unable to GC interface")
	}
}

func removeIPv4Addresses(ctx context.Context, ec2client *ec2.EC2, iface *ec2.NetworkInterface, ipv4AddressesToRemove []string, errCh chan error, limiter *concurrencyLimiter) {
	ctx, span := trace.StartSpan(ctx, "removeIPv4Addresses")
	defer span.End()

	// This might make it so that database trasnactions are held longer than neccessary.
	if err := limiter.awsv4ratelimiter.Wait(ctx); err != nil {
		span.SetStatus(traceStatusFromError(err))
		errCh <- err
		return
	}

	logger.G(ctx).WithField("ipv4AddressesToRemove", ipv4AddressesToRemove).Debug("Removing IPv4 Addresses")
	_, err := ec2client.UnassignPrivateIpAddresses(&ec2.UnassignPrivateIpAddressesInput{
		PrivateIpAddresses: aws.StringSlice(ipv4AddressesToRemove),
		NetworkInterfaceId: iface.NetworkInterfaceId,
	})
	logger.G(ctx).WithError(err).Debug("Removed IPv4 Addresses")

	errCh <- err
}

func removeIPv6Addresses(ctx context.Context, ec2client *ec2.EC2, iface *ec2.NetworkInterface, ipv6AddressesToRemove []string, errCh chan error, limiter *concurrencyLimiter) {
	ctx, span := trace.StartSpan(ctx, "removeIPv6Addresses")
	defer span.End()

	// This might make it so that database trasnactions are held longer than neccessary.
	if err := limiter.awsv4ratelimiter.Wait(ctx); err != nil {
		span.SetStatus(traceStatusFromError(err))
		errCh <- err
		return
	}

	logger.G(ctx).WithField("ipv6AddressesToRemove", ipv6AddressesToRemove).Debug("Removing IPv6 Addresses")
	_, err := ec2client.UnassignIpv6Addresses(&ec2.UnassignIpv6AddressesInput{
		Ipv6Addresses:      aws.StringSlice(ipv6AddressesToRemove),
		NetworkInterfaceId: iface.NetworkInterfaceId,
	})
	logger.G(ctx).WithError(err).Debug("Removed IPv6 Addresses")
	errCh <- err
}
