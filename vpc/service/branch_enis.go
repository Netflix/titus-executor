package service

import (
	"context"
	"database/sql"
	"sort"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/lib/pq"
)

func insertBranchENIIntoDB(ctx context.Context, tx *sql.Tx, iface *ec2.NetworkInterface) error {
	securityGroupIds := make([]string, len(iface.Groups))
	for idx := range iface.Groups {
		securityGroupIds[idx] = aws.StringValue(iface.Groups[idx].GroupId)
	}
	sort.Strings(securityGroupIds)

	_, err := tx.ExecContext(ctx, "INSERT INTO branch_enis (branch_eni, subnet_id, account_id, az, vpc_id, security_groups, modified_at) VALUES ($1, $2, $3, $4, $5, $6, transaction_timestamp()) ON CONFLICT (branch_eni) DO NOTHING",
		aws.StringValue(iface.NetworkInterfaceId),
		aws.StringValue(iface.SubnetId),
		aws.StringValue(iface.OwnerId),
		aws.StringValue(iface.AvailabilityZone),
		aws.StringValue(iface.VpcId),
		pq.Array(securityGroupIds),
	)

	return err
}
