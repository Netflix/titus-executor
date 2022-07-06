package service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/data"
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

func (vpcService *vpcService) reconcileSubnetCIDRReservationsLoop(ctx context.Context, protoItem data.KeyedItem) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	item := protoItem.(*data.Subnet)
	for {
		var resetTime time.Duration
		err := vpcService.doReconcileSubnetCIDRReservations(ctx, item)
		if err != nil {
			logger.G(ctx).WithField("region", item.Region).WithField("accountID", item.AccountID).WithError(err).Error("Failed to reconcile subnet CIDR Reservations")
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

func (vpcService *vpcService) doReconcileSubnetCIDRReservations(ctx context.Context, subnet *data.Subnet) error {
	ctx, span := trace.StartSpan(ctx, "doReconcileSubnetCIDRReservations")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("subnet", subnet.SubnetID),
		trace.StringAttribute("accountID", subnet.AccountID),
		trace.StringAttribute("az", subnet.Az),
	)
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"subnet":    subnet.SubnetID,
		"accountID": subnet.AccountID,
		"az":        subnet.Az,
	})
	logger.G(ctx).Debug("Beginning reconcilation of Subnet CIDR Reservations")

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{AccountID: subnet.AccountID, Region: subnet.Region})
	if err != nil {
		err = errors.Wrap(err, "Cannot get EC2 session")
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	reservations, err := session.GetSubnetCidrReservations(ctx, subnet.SubnetID)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	v6reservations := make([]*ec2.SubnetCidrReservation, 0, len(reservations))
	v4reservations := make([]*ec2.SubnetCidrReservation, 0, len(reservations))
	v6scrIDs := sets.NewString()
	v4scrIDs := sets.NewString()
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
			v6scrIDs.Insert(aws.StringValue(reservation.SubnetCidrReservationId))
		} else {
			v4reservations = append(v4reservations, reservation)
			v4scrIDs.Insert(aws.StringValue(reservation.SubnetCidrReservationId))
		}
	}

	v6reservationsInDB := sets.NewString()
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = fmt.Errorf("Could not start database transaction: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, "SELECT reservation_id FROM subnet_cidr_reservations_v6 WHERE subnet_id = $1", subnet.ID)
	if err != nil {
		err = fmt.Errorf("Cannot query subnet_cidr_reservations_v6: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	defer func(r *sql.Rows) {
		_ = r.Close()
	}(rows)

	for rows.Next() {
		var reservationID string
		err = rows.Scan(&reservationID)
		if err != nil {
			err = fmt.Errorf("Cannot scan row: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
		v6reservationsInDB.Insert(reservationID)
	}

	v6reservationsToDelete := v6reservationsInDB.Difference(v6scrIDs)
	if v6reservationsToDelete.Len() > 0 {
		_, err = tx.ExecContext(ctx, "DELETE FROM subnet_cidr_reservations_v6 WHERE reservation_id = any($1)", pq.Array(v6reservationsToDelete.UnsortedList()))
		if err != nil {
			if err != nil {
				err = fmt.Errorf("Unable to delete non-existent subnet CIDR Reservation groups: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	for _, reservation := range v6reservations {
		if v6reservationsInDB.Has(aws.StringValue(reservation.SubnetCidrReservationId)) {
			continue
		}

		// Try inserting this into the DB.
		_, err = tx.ExecContext(ctx, `
INSERT INTO subnet_cidr_reservations_v6 (reservation_id, subnet_id, prefix, type, description) VALUES ($1, $2, $3, $4, $5)
`,
			aws.StringValue(reservation.SubnetCidrReservationId),
			subnet.ID,
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

	v4reservationsInDB := sets.NewString()
	rows, err = tx.QueryContext(ctx, "SELECT reservation_id FROM subnet_cidr_reservations_v4 WHERE subnet_id = $1", subnet.ID)
	if err != nil {
		err = fmt.Errorf("Cannot query subnet_cidr_reservations_v4: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	defer func(r *sql.Rows) {
		_ = r.Close()
	}(rows)

	for rows.Next() {
		var reservationID string
		err = rows.Scan(&reservationID)
		if err != nil {
			err = fmt.Errorf("Cannot scan row: %w", err)
			tracehelpers.SetStatus(err, span)
			return err
		}
		v4reservationsInDB.Insert(reservationID)
	}

	v4reservationsToDelete := v4reservationsInDB.Difference(v4scrIDs)
	if v4reservationsToDelete.Len() > 0 {
		_, err = tx.ExecContext(ctx, "DELETE FROM subnet_cidr_reservations_v4 WHERE reservation_id = any($1)", pq.Array(v4reservationsToDelete.UnsortedList()))
		if err != nil {
			if err != nil {
				err = fmt.Errorf("Unable to delete non-existent subnet CIDR Reservation groups: %w", err)
				tracehelpers.SetStatus(err, span)
				return err
			}
		}
	}

	for _, reservation := range v4reservations {
		if v4reservationsInDB.Has(aws.StringValue(reservation.SubnetCidrReservationId)) {
			continue
		}

		// Try inserting this into the DB.
		_, err = tx.ExecContext(ctx, `
INSERT INTO subnet_cidr_reservations_v4 (reservation_id, subnet_id, prefix, type, description) VALUES ($1, $2, $3, $4, $5)
`,
			aws.StringValue(reservation.SubnetCidrReservationId),
			subnet.ID,
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
