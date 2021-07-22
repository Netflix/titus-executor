package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	timeBetweenSubnetCIDRReservationReconcilation = 5 * time.Minute
)

func (vpcService *vpcService) reconcileSubnetCIDRReservationsLongLivedTask() longLivedTask {
	return longLivedTask{
		taskName:   "reconcile_subnet_cidr_reservations",
		itemLister: vpcService.getSubnets,
		workFunc:   vpcService.reconcileSubnetCIDRReservationsLoop,
	}
}

func (vpcService *vpcService) reconcileSubnetCIDRReservationsLoop(ctx context.Context, protoItem keyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*subnet)
	for {
		var resetTime time.Duration
		err := vpcService.doReconcileSubnetCIDRReservations(ctx, item)
		if err != nil {
			logger.G(ctx).WithField("region", item.region).WithField("accountID", item.accountID).WithError(err).Error("Failed to reconcile subnet CIDR Reservations")
			resetTime = timeBetweenErrors
		} else {
			resetTime = timeBetweenSubnetCIDRReservationReconcilation
		}
		err = waitFor(ctx, resetTime)
		if err != nil {
			return err
		}
	}
}

func (vpcService *vpcService) doReconcileSubnetCIDRReservations(ctx context.Context, subnet *subnet) error {
	ctx, span := trace.StartSpan(ctx, "doReconcileSubnetCIDRReservations")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("subnet", subnet.subnetID),
		trace.StringAttribute("accountID", subnet.accountID),
		trace.StringAttribute("az", subnet.az),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"subnet":    subnet.subnetID,
		"accountID": subnet.accountID,
		"az":        subnet.az,
	})
	logger.G(ctx).Debug("Beginning reconcilation of Subnet CIDR Reservations")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: subnet.accountID, Region: subnet.region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	reservations, err := session.GetSubnetCidrReservations(ctx, subnet.subnetID)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	v6reservations := make([]*ec2.SubnetCidrReservation, 0, len(reservations))
	scrIDs := sets.NewString()
	for idx := range reservations {
		reservation := reservations[idx]
		ip, _, err := net.ParseCIDR(aws.StringValue(reservation.Cidr))
		if err != nil {
			err = fmt.Errorf("Cannot parse subnet CIDR %q: %w", aws.StringValue(reservation.Cidr), err)
			tracehelpers.SetStatus(err, span)
			return err
		}

		if ip.To4() == nil {
			v6reservations = append(v6reservations, reservation)
			scrIDs.Insert(aws.StringValue(reservation.SubnetCidrReservationId))
		}
	}

	reservationsInDB := sets.NewString()
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = fmt.Errorf("Could not start database transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, "SELECT reservation_id FROM subnet_cidr_reservations_v6 WHERE subnet_id = $1", subnet.id)
	if err != nil {
		err = fmt.Errorf("Cannot query subnet_cidr_reservations_v6: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var reservationID string
		err = rows.Scan(&reservationID)
		if err != nil {
			err = fmt.Errorf("Cannot scan row: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
		reservationsInDB.Insert(reservationID)
	}

	reservationsToDelete := reservationsInDB.Difference(scrIDs)
	if reservationsToDelete.Len() > 0 {
		_, err = tx.ExecContext(ctx, "DELETE FROM subnet_cidr_reservations_v6 WHERE reservation_id = any($1)", pq.Array(reservationsToDelete.UnsortedList()))
		if err != nil {
			if err != nil {
				err = fmt.Errorf("Unable to delete non-existent subnet CIDR Reservation groups: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	for _, reservation := range v6reservations {
		if reservationsInDB.Has(aws.StringValue(reservation.SubnetCidrReservationId)) {
			continue
		}

		// Try inserting this into the DB.
		_, err = tx.ExecContext(ctx, `
INSERT INTO subnet_cidr_reservations_v6 (reservation_id, subnet_id, prefix, type, description) VALUES ($1, $2, $3, $4, $5)
`,
			aws.StringValue(reservation.SubnetCidrReservationId),
			subnet.id,
			aws.StringValue(reservation.Cidr),
			aws.StringValue(reservation.ReservationType),
			aws.StringValue(reservation.Description),
		)
		if err != nil {
			err = fmt.Errorf("Cannot insert reservation %s into database: %w", reservation.String(), err)
			tracehelpers.SetStatus(err, span)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		err = fmt.Errorf("Cannot commit transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}
