package service

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws/awserr"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
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

func (vpcService *vpcService) doGCAttachedENIs(ctx context.Context, region, accountID string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doGCAttachedENIs")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("region", region),
		trace.StringAttribute("accountID", accountID),
	)

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
		MaxResults: aws.Int64(100),
	}
	for {
		describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, &describeNetworkInterfacesInput)
		if err != nil {
			err = errors.Wrap(err, "Cannot not describe network interfaces")
			span.SetStatus(traceStatusFromError(err))
			return err
		}

		for _, iface := range describeNetworkInterfacesOutput.NetworkInterfaces {
			err = vpcService.doGCAttachedENI(ctx, iface)
			if err != nil {
				err = errors.Wrap(err, "Cannot GC network interface")
				span.SetStatus(traceStatusFromError(err))
				return err
			}
		}

		if describeNetworkInterfacesOutput.NextToken == nil {
			return nil
		}
		describeNetworkInterfacesInput.NextToken = describeNetworkInterfacesOutput.NextToken
	}
}

func (vpcService *vpcService) doGCAttachedENI(ctx context.Context, iface *ec2.NetworkInterface) error {
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx, `
SELECT association_id
FROM branch_eni_attachments
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE branch_eni_attachments.branch_eni = $1
  AND attachment_generation = 3
  AND COALESCE(last_assigned_to, TIMESTAMP 'EPOCH') < transaction_timestamp() - INTERVAL '1 minutes'
  FOR
  UPDATE
`, aws.StringValue(iface.NetworkInterfaceId))
	var associationID string
	err = row.Scan(&associationID)
	if err == sql.ErrNoRows {
		return nil
	}

	if err != nil {
		err = errors.Wrap(err, "Cannot scan row")
		return err
	}

	/*
			row = tx.QueryRowContext(ctx, `
		SELECT (array_agg(host(ipv4addr)) FILTER (WHERE ipv4addr IS NOT NULL)),
		       (array_agg(host(ipv6addr)) FILTER (WHERE ipv6addr IS NOT NULL))
		FROM assignments
		WHERE branch_eni_association = $1
		`, associationID)
			var ipv4addrs, ipv6addrs []string
			err = row.Scan(pq.Array(&ipv4addrs), pq.Array(&ipv6addrs))
			if err != nil {
				err = errors.Wrap(err, "Cannot scan row with used ipv4addrs / ipv6addrs")
				return err
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
			removableIPv6Addresses := interfaceIPv6Addresses.Difference(sets.NewString(ipv6addrs...))
			removableIPv4Addresses := interfaceIPv4Addresses.Difference(sets.NewString(ipv4addrs...))

			rows, err := tx.QueryContext(ctx, "SELECT ip_address FROM ip_last_used_v3 WHERE host(ip_address) = any($1) AND vpc_id = $2 AND now() - last_seen < INTERVAL '2 MINUTE'", pq.Array(removableIPv4Addresses.List()), aws.StringValue(iface.VpcId))
			if err != nil {
				err = errors.Wrap(err, "Cannot query for ipv4 addresses which may have been allocated in the last 2 minutes")
				return err
			}
			for rows.Next() {
				var ipv4Address string
				err = rows.Scan(&ipv4Address)
				if err != nil {
					err = errors.Wrap(err, "Cannot scan address")
					return err
				}
				removableIPv4Addresses.Delete(ipv4Address)
			}

			rows, err = tx.QueryContext(ctx, "SELECT ip_address FROM ip_last_used_v3 WHERE host(ip_address) = any($1) AND vpc_id = $2 AND now() - last_seen < INTERVAL '2 MINUTE'", pq.Array(removableIPv6Addresses.List()), aws.StringValue(iface.VpcId))
			if err != nil {
				err = errors.Wrap(err, "Cannot query for ipv4 addresses which may have been allocated in the last 2 minutes")
				return err
			}
			for rows.Next() {
				var ipv6Address string
				err = rows.Scan(&ipv6Address)
				if err != nil {
					err = errors.Wrap(err, "Cannot scan address")
					return err
				}
				removableIPv6Addresses.Delete(ipv6Address)
			}

			logger.G(ctx).
				WithField("interface", aws.StringValue(iface.NetworkInterfaceId)).
				WithField("ipv4addrs", ipv4addrs).
				WithField("ipv6addrs", ipv6addrs).
				WithField("removableIPv6Addresses", removableIPv6Addresses.List()).
				WithField("removableIPv4Addresses", removableIPv4Addresses.List()).
				Debug("Scanned row")
	*/
	return nil
}
