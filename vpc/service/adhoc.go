package service

import (
	"context"
	"database/sql"

	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	ccache "github.com/karlseguin/ccache/v2"
	"golang.org/x/time/rate"
)

const (
	SUBNETID = "subnet-09bf4843"
)

func RunAdhocCommand(ctx context.Context, db *sql.DB, ec2 *ec2wrapper.EC2SessionManager) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	vpcService := &vpcService{
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
	_, err := vpcService.doDetatchUnusedBranchENI(ctx, &s)
	return err
}
