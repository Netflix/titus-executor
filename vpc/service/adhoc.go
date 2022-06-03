package service

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"go.opencensus.io/trace"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	ccache "github.com/karlseguin/ccache/v2"
	"golang.org/x/time/rate"
)

const (
	SUBNETID = "subnet-09bf4843"
)

func RunAdhocCommand(ctx context.Context, db *sql.DB, ec2 *ec2wrapper.EC2SessionManager, branchEni string, associationId string) error {
	service := &vpcService{
		hostname: "adhoc",
		ec2:      ec2wrapper.NewEC2SessionManager("adhoc"),
		db:       db,
		dbURL:    "",
		dbRateLimiter: rate.NewLimiter(1000, 1),
		trunkTracker:              newTrunkTrackerCache(),
		invalidSecurityGroupCache: ccache.New(ccache.Configure()),
	}

	s := subnet{
		id:        411,
		az:        "us-east-1c",
		vpcID:     "vpc-4de2b628",
		accountID: "149510111645",
		subnetID:  "subnet-09bf4843",
		cidr:      "100.112.0.0/16",
		region:    "us-east-1",
	}
	err := service.doDetatchUnusedBranchENIKyle(db, ec2, &s, branchEni, associationId)
	return err
}

func(vpcService *vpcService) doDetatchUnusedBranchENIKyle(
		db *sql.DB,
		ec2 *ec2wrapper.EC2SessionManager,
		subnet *subnet, branchENI string, associationId string) error {

	ctx, cancel := context.WithTimeout(context.TODO(), 10 * time.Minute)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "doDetatchUnusedBranchENI")
	defer span.End()

	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()


	span.AddAttributes(trace.StringAttribute("eni", branchENI))
	logger.G(ctx).WithField("eni", branchENI).Info("Disassociating ENI")

	session, err := ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
		Region:    subnet.region,
		AccountID: subnet.accountID,
	})
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}

	//disassociateNetworkInterface(ctx context.Context, tx *sql.Tx, session *ec2wrapper.EC2Session, associationID string, force bool) error {
	err = vpcService.disassociateNetworkInterface(ctx, tx, session, associationId, false)
	if err != nil {
		err2 := tx.Commit()
		if err2 != nil {
			tracehelpers.SetStatus(err, span)
			return err2
		}
		fmt.Println(err, "Cannot disassociate network interface")
		logger.G(ctx).WithError(err).Error("Experienced error while trying to disassociate network interface")
		tracehelpers.SetStatus(err, span)
		return err
	}

	tx.Commit()
	if err != nil {
		span.SetStatus(traceStatusFromError(err))
		return err
	}
	return nil
}

