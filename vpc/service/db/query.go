package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/lib/pq"
)

func getLeastUsedSubnetByAccount(ctx context.Context, tx *sql.Tx, accountID, az string) *sql.Row {
	row := tx.QueryRowContext(ctx, `
	WITH usable_subnets AS
	  (SELECT subnets.az,
	          subnets.vpc_id,
	          subnets.account_id,
	          subnets.subnet_id,
	          subnets.cidr,
	          availability_zones.region
	   FROM subnets
	   JOIN account_mapping ON subnets.subnet_id = account_mapping.subnet_id
	   JOIN availability_zones ON subnets.az = availability_zones.zone_name
	   AND subnets.account_id = availability_zones.account_id
	   WHERE subnets.account_id = $1
	     AND subnets.az = $2)
	SELECT *
	FROM usable_subnets
	ORDER BY
	  (SELECT count(ipv4addr)
	   FROM branch_enis
	   LEFT JOIN branch_eni_attachments bea ON branch_enis.branch_eni = bea.branch_eni
	   LEFT JOIN assignments ON bea.association_id = branch_eni_association
	   WHERE subnet_id = usable_subnets.subnet_id
	     AND bea.state = 'attached' ) ASC
	LIMIT 1
	`,
		accountID, az)
	return row
}

func getLeastUsedSubnetBySubnetIDs(ctx context.Context, tx *sql.Tx, subnetIDs []string, az string) *sql.Row {
	row := tx.QueryRowContext(ctx, `
	WITH usable_subnets AS
	  (SELECT subnets.az,
	          subnets.vpc_id,
	          subnets.account_id,
	          subnets.subnet_id,
	          subnets.cidr,
	          availability_zones.region
	   FROM subnets
	   JOIN availability_zones ON subnets.az = availability_zones.zone_name
	   AND subnets.account_id = availability_zones.account_id
	   WHERE subnets.az = $1
	     AND subnets.subnet_id = any($2))
	SELECT *
	FROM usable_subnets
	ORDER BY
	  (SELECT count(ipv4addr)
	   FROM branch_enis
	   LEFT JOIN branch_eni_attachments bea ON branch_enis.branch_eni = bea.branch_eni
	   LEFT JOIN assignments ON bea.association_id = branch_eni_association
	   WHERE subnet_id = usable_subnets.subnet_id
	     AND bea.state = 'attached' ) ASC
	LIMIT 1
	`, az, pq.Array(subnetIDs))
	return row
}

// Get the least used subnet (i.e. subnet with the least number of IPs) in the given subnetIDs.
// If the given subnetIDs is empty, then get the least used subnet by the given accountID
func GetLeastUsedSubnet(ctx context.Context, tx *sql.Tx, az, accountID string, subnetIDs []string) (*data.Subnet, error) {
	var row *sql.Row
	if len(subnetIDs) == 0 {
		row = getLeastUsedSubnetByAccount(ctx, tx, accountID, az)
	} else {
		row = getLeastUsedSubnetBySubnetIDs(ctx, tx, subnetIDs, az)
	}
	ret := data.Subnet{}
	err := row.Scan(&ret.Az, &ret.VpcID, &ret.AccountID, &ret.SubnetID, &ret.Cidr, &ret.Region)
	if err == sql.ErrNoRows {
		if len(subnetIDs) > 0 {
			err = vpcerrors.NewNotFoundError(fmt.Errorf("no subnet found matching IDs %s in az %s", subnetIDs, az))
		} else {
			err = vpcerrors.NewNotFoundError(fmt.Errorf("no subnet found in account %s in az %s", accountID, az))
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func GetStaticAllocationByID(ctx context.Context, tx *sql.Tx, id string) (*data.StaticAllocation, error) {
	row := tx.QueryRowContext(ctx, "SELECT az, region, subnet_id FROM ip_addresses WHERE id = $1", id)
	var staticAllocation data.StaticAllocation
	err := row.Scan(&staticAllocation.Az, &staticAllocation.Region, &staticAllocation.SubnetID)
	if err != nil {
		return nil, err
	}
	return &staticAllocation, nil
}
