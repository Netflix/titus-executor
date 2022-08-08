package db

// This file contains all DB queries used by VPC Service

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/data"
	"github.com/Netflix/titus-executor/vpc/service/vpcerrors"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"go.opencensus.io/stats"
	"k8s.io/apimachinery/pkg/util/sets"
)

func getLeastUsedSubnetByAccount(ctx context.Context, tx *sql.Tx, accountID, az string) *sql.Row {
	start := time.Now()
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
	stats.Record(ctx, getLeastUsedSubnetByAccountLatency.M(time.Since(start).Milliseconds()))
	return row
}

func getLeastUsedSubnetBySubnetIDs(ctx context.Context, tx *sql.Tx, subnetIDs []string, az string) *sql.Row {
	start := time.Now()
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
	stats.Record(ctx, getLeastUsedSubnetBySubnetIDsLatency.M(time.Since(start).Milliseconds()))
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

// Get the static allocation by ID and lock the row until the end of the given transaction
func GetStaticAllocationByIDAndLock(ctx context.Context, tx *sql.Tx, id string) (*data.StaticAllocation, error) {
	row := tx.QueryRowContext(ctx, "SELECT ip_address, subnet_id FROM ip_addresses WHERE id = $1 FOR UPDATE", id)
	staticAllocation := &data.StaticAllocation{}
	err := row.Scan(&staticAllocation.IP, &staticAllocation.SubnetID)
	if err == sql.ErrNoRows {
		return nil, err
	}
	return staticAllocation, nil
}

// Returns (Assignment, completed, error) and lock the assignment row until the
func GetAndLockAssignmentByTaskID(ctx context.Context, tx *sql.Tx, taskID string) (*data.Assignment, bool, error) {
	start := time.Now()
	row := tx.QueryRowContext(ctx, `
SELECT assignments.id,
       bea.branch_eni,
       bea.trunk_eni,
       bea.idx,
       assignments.branch_eni_association,
       ipv4addr,
       ipv6addr,
       completed,
       jumbo,
       bandwidth,
       ceil,
       be.subnet_id
FROM assignments
JOIN branch_eni_attachments bea ON assignments.branch_eni_association = bea.association_id
JOIN branch_enis be on bea.branch_eni = be.branch_eni
WHERE assignment_id = $1
  FOR NO KEY
  UPDATE OF assignments`, taskID)
	stats.Record(ctx, getAndLockAssignmentByTaskIDLatency.M(time.Since(start).Milliseconds()))
	var completed bool

	assignment := &data.Assignment{AssignmentID: taskID}
	err := row.Scan(&assignment.ID, &assignment.BranchENI, &assignment.TrunkENI, &assignment.VlanID,
		&assignment.AssociationID, &assignment.IPv4Addr, &assignment.IPv6Addr, &completed,
		&assignment.Jumbo, &assignment.Bandwidth, &assignment.Ceil, &assignment.SubnetID)
	if err != nil {
		return nil, false, err
	}
	return assignment, completed, nil
}

// Get the assignment and lock
func GetAndLockAssignmentByID(ctx context.Context, tx *sql.Tx, id int) (*data.Assignment, error) {
	assignment := &data.Assignment{ID: id}
	start := time.Now()
	row := tx.QueryRowContext(ctx, `
SELECT assignment_id, cidr, ipv4addr, ipv6addr
FROM assignments 
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
JOIN subnets on branch_enis.subnet_id = subnets.subnet_id
WHERE assignments.id = $1 FOR NO KEY UPDATE OF assignments
`, id)
	stats.Record(ctx, getAndLockAssignmentByAssignmentIDLatency.M(time.Since(start).Milliseconds()))
	err := row.Scan(&assignment.AssignmentID, &assignment.CIDR, &assignment.IPv4Addr, &assignment.IPv6Addr)
	if err != nil {
		return nil, err
	}
	return assignment, nil
}

func GetBranchENI(ctx context.Context, tx *sql.Tx, branchENI string) (*api.NetworkInterface, error) {
	nif := &api.NetworkInterface{}
	row := tx.QueryRowContext(ctx, "SELECT subnet_id, az, mac, branch_eni, account_id, vpc_id FROM branch_enis WHERE branch_eni = $1",
		branchENI)
	err := row.Scan(&nif.SubnetId,
		&nif.AvailabilityZone,
		&nif.MacAddress,
		&nif.NetworkInterfaceId,
		&nif.OwnerAccountId,
		&nif.VpcId)
	if err != nil {
		return nil, err
	}
	return nif, nil
}

func GetTrunkENI(ctx context.Context, tx *sql.Tx, trunkENI string) (*api.NetworkInterface, error) {
	nif := &api.NetworkInterface{}
	row := tx.QueryRowContext(ctx, "SELECT subnet_id, az, mac, trunk_eni, account_id, vpc_id FROM trunk_enis WHERE trunk_eni = $1",
		trunkENI)
	err := row.Scan(&nif.SubnetId,
		&nif.AvailabilityZone,
		&nif.MacAddress,
		&nif.NetworkInterfaceId,
		&nif.OwnerAccountId,
		&nif.VpcId)
	if err != nil {
		return nil, err
	}
	return nif, nil
}

func GetCIDRBySubnet(ctx context.Context, tx *sql.Tx, subnetID string) (net.IP, *net.IPNet, error) {
	var subnetCIDR string
	row := tx.QueryRowContext(ctx, "SELECT cidr FROM subnets WHERE subnet_id = $1", subnetID)
	err := row.Scan(&subnetCIDR)
	if err != nil {
		err = fmt.Errorf("could not find CIDR by subnet %q: %w", subnetID, err)
		return nil, nil, err
	}
	ip, ipnet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		err = fmt.Errorf("could not parse subnet CIDR %q: %w", subnetCIDR, err)
		return nil, nil, err
	}
	return ip, ipnet, err
}

func GetElasticAddressByTaskID(ctx context.Context, tx *sql.Tx, taskID string) (*api.ElasticAddress, error) {
	row := tx.QueryRowContext(ctx, `
	SELECT elastic_ip_attachments.elastic_ip_allocation_id,
		   association_id,
		   public_ip
	FROM elastic_ip_attachments
	JOIN elastic_ips ON elastic_ip_attachments.elastic_ip_allocation_id = elastic_ips.allocation_id
	WHERE assignment_id = $1`, taskID)
	var elasticIPAllocationID, elasticIPAssociationID, publicIP string
	err := row.Scan(&elasticIPAllocationID, &elasticIPAssociationID, &publicIP)
	if err != nil {
		return nil, err
	}
	return &api.ElasticAddress{
		Ip:             publicIP,
		AllocationId:   elasticIPAllocationID,
		AssociationdId: elasticIPAssociationID,
	}, nil
}

func GetElasticIPAttachmentByTaskID(ctx context.Context, tx *sql.Tx, taskID string) (*data.ElasticIPAttachment, error) {
	row := tx.QueryRowContext(ctx, `
SELECT elastic_ip_attachments.id,
       account_id,
       region,
       association_id
FROM elastic_ip_attachments
JOIN elastic_ips ON elastic_ip_attachments.elastic_ip_allocation_id = elastic_ips.allocation_id
WHERE elastic_ip_attachments.assignment_id = $1
`, taskID)
	elasticIPAttachment := &data.ElasticIPAttachment{}
	err := row.Scan(&elasticIPAttachment.ID, &elasticIPAttachment.AccountID,
		&elasticIPAttachment.Region, &elasticIPAttachment.AssociationID)
	if err != nil {
		return nil, err
	}
	return elasticIPAttachment, nil
}

func GetClassIDByAssignmentID(ctx context.Context, tx *sql.Tx, assignmentID int) (uint32, error) {
	row := tx.QueryRowContext(ctx, "SELECT class_id FROM htb_classid WHERE assignment_id = $1", assignmentID)
	var classID uint32
	var err = row.Scan(&classID)
	if err != nil {
		return 0, err
	}
	return classID, nil
}

// Get security groups of the given branch ENI and lock the row
func GetSecurityGroupsAndLockBranchENI(ctx context.Context, tx *sql.Tx, branchENI string) ([]string, error) {
	// This locks the branch ENI making this whole process "exclusive"
	row := tx.QueryRowContext(ctx, "SELECT security_groups FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", branchENI)
	var securityGroups []string
	err := row.Scan(pq.Array(&securityGroups))
	if err != nil {
		return nil, err
	}
	return securityGroups, nil
}

// Get one available elastic IP from the given allocationID list
// Also lock the IP until the end of given transaction.
func GetAvailableElasticAddressByAllocationIDsAndLock(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
	borderGroup string,
	allocationIDs []string) (*api.ElasticAddress, error) {
	row := tx.QueryRowContext(ctx, `
SELECT allocation_id, public_ip
FROM elastic_ips
WHERE account_id = $1
  AND allocation_id NOT IN
    (SELECT elastic_ip_allocation_id
     FROM elastic_ip_attachments)
  AND network_border_group = $2
  AND allocation_id = any($3)
LIMIT 1
FOR
UPDATE OF elastic_ips
`, accountID, borderGroup, pq.Array(allocationIDs))
	elasticAddress := api.ElasticAddress{}
	err := row.Scan(&elasticAddress.AllocationId, &elasticAddress.Ip)
	if err != nil {
		return nil, err
	}
	return &elasticAddress, nil
}

// Get one available elastic IP from the given group
// Also lock the IP until the end of given transaction.
func GetAvailableElasticAddressByGroupAndLock(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
	borderGroup string,
	groupName string) (*api.ElasticAddress, error) {
	row := tx.QueryRowContext(ctx, `
SELECT allocation_id, public_ip
FROM elastic_ips
WHERE account_id = $1
  AND allocation_id NOT IN
    (SELECT elastic_ip_allocation_id
     FROM elastic_ip_attachments)
  AND network_border_group = $2
  AND tags->>'titus_vpc_pool' = $3
LIMIT 1
FOR
UPDATE of elastic_ips
`, accountID, borderGroup, groupName)
	elasticAddress := api.ElasticAddress{}
	err := row.Scan(&elasticAddress.AllocationId, &elasticAddress.Ip)
	if err != nil {
		return nil, err
	}
	return &elasticAddress, nil
}

func GetBorderGroupByAzAndAccount(
	ctx context.Context,
	tx *sql.Tx,
	az string,
	accountID string) (string, error) {
	row := tx.QueryRowContext(ctx, "SELECT network_border_group FROM availability_zones WHERE zone_name = $1 AND account_id = $2",
		az, accountID)
	var borderGroup string
	err := row.Scan(&borderGroup)
	if err != nil {
		return "", err
	}
	return borderGroup, nil
}

// Get all IPv4 addresses of the given ENI assocation that are already assigned to continers.
func GetUsedIPv4AddressesByENIAssociation(
	ctx context.Context,
	tx *sql.Tx,
	branchENIAssociationID string) (sets.String, error) {

	usedIPAddresses := sets.NewString()
	rows, err := tx.QueryContext(ctx, "SELECT ipv4addr FROM assignments WHERE ipv4addr IS NOT NULL AND branch_eni_association = $1", branchENIAssociationID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var address string
		err = rows.Scan(&address)
		if err != nil {
			return nil, err
		}
		usedIPAddresses.Insert(address)
	}
	return usedIPAddresses, nil
}

// For the given IPv4 addresses, find those are static IPs and return
func GetStaticIPv4Addresses(
	ctx context.Context,
	tx *sql.Tx, ips []string, subnetID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT ip_address FROM ip_addresses WHERE host(ip_address) = any($1) AND subnet_id = $2",
		pq.Array(ips), subnetID)
	if err != nil {
		return nil, err
	}
	staticIPAddresses := make([]string, 0)
	for rows.Next() {
		var staticIPAddress string
		err = rows.Scan(&staticIPAddress)
		if err != nil {
			return nil, err
		}
		staticIPAddresses = append(staticIPAddresses, staticIPAddress)
	}
	return staticIPAddresses, nil
}

// For the given list of IPs, find an available one with the oldest last_seen value
func GetOldestAvailableIPv4(ctx context.Context, tx *sql.Tx, ips []string, vpcID string) (string, error) {
	row := tx.QueryRowContext(ctx, "SELECT ip_address FROM ip_last_used_v3 WHERE ip_address = any($1::inet[]) AND vpc_id = $2 ORDER BY last_seen ASC LIMIT 1",
		pq.Array(ips), vpcID)
	var ipAddress string
	err := row.Scan(&ipAddress)
	if err != nil {
		return "", err
	}
	return ipAddress, nil
}

// Given a task ID, get the static IP assigned to the task
func GetAssignedStaticIPAddressByTaskID(ctx context.Context, tx *sql.Tx, taskID string) (*data.StaticIPAddress, error) {
	row := tx.QueryRowContext(ctx, `
SELECT branch_enis.branch_eni,
       branch_enis.az,
       branch_enis.account_id,
       ip_address,
       home_eni
FROM ip_address_attachments
JOIN ip_addresses ON ip_address_attachments.ip_address_uuid = ip_addresses.id
JOIN assignments ON ip_address_attachments.assignment_id = assignments.assignment_id
JOIN branch_eni_attachments ON assignments.branch_eni_association = branch_eni_attachments.association_id
JOIN branch_enis ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
WHERE ip_address_attachments.assignment_id = $1
`, taskID)
	staticIPAddress := &data.StaticIPAddress{}
	err := row.Scan(&staticIPAddress.BranchENI, &staticIPAddress.AZ, &staticIPAddress.AccountID, &staticIPAddress.IP, &staticIPAddress.HomeENI)
	if err != nil {
		return nil, err
	}
	return staticIPAddress, nil
}

// Returns (vpcID, branchENI, error)
func GetVpcIDAndBranchENIByAssociationID(ctx context.Context, tx *sql.Tx, associationID string) (string, string, error) {
	row := tx.QueryRowContext(ctx, `
	SELECT vpc_id, branch_enis.branch_eni FROM branch_enis 
	JOIN branch_eni_attachments ON branch_eni_attachments.branch_eni = branch_enis.branch_eni
	WHERE branch_eni_attachments.association_id = $1`, associationID)
	var vpcID, branchENI string
	err := row.Scan(&vpcID, &branchENI)
	if err != nil {
		return "", "", err
	}
	return vpcID, branchENI, nil
}

func GetAllBranchENIsByAccountRegion(ctx context.Context, tx *sql.Tx, accountID, region string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `
	SELECT branch_enis.branch_eni
	FROM branch_enis
	JOIN availability_zones ON branch_enis.account_id = availability_zones.account_id
	  AND branch_enis.az = availability_zones.zone_name
	WHERE branch_enis.account_id = $1
	  AND availability_zones.region = $2
	ORDER BY RANDOM()
	  `, accountID, region)
	if err != nil {
		err = errors.Wrap(err, "Could not get all branch ENIs from DB")
		return nil, err
	}

	enis := make([]string, 0)
	for rows.Next() {
		var eni string
		err = rows.Scan(&eni)
		if err != nil {
			err = errors.Wrap(err, "Could not scan branch eni ID")
			return nil, err
		}
		enis = append(enis, eni)
	}
	return enis, nil
}

// Get one branch ENI that is not assigned to any container
// random: If true, select a random unassigned branch ENI. Otherwise, select the oldest one.
func GetUnassignedBranchENI(ctx context.Context, tx *sql.Tx, subnet, trunkENI string, random bool) (*data.BranchENI, error) {
	branchENI := &data.BranchENI{}
	var row *sql.Row
	if random {
		row = tx.QueryRowContext(ctx, `
SELECT valid_branch_enis.id,
       valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.az,
       valid_branch_enis.account_id,
       valid_branch_enis.idx
FROM
  (SELECT branch_enis.id,
          branch_enis.branch_eni,
          branch_enis.az,
          branch_enis.account_id,
          branch_eni_attachments.idx,
          branch_eni_attachments.association_id,
     (SELECT count(*)
      FROM assignments
      WHERE assignments.branch_eni_association = branch_eni_attachments.association_id) AS c
   FROM branch_enis
   JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
   WHERE subnet_id = $1
     AND trunk_eni = $2
     AND (SELECT count(*) FROM subnet_usable_prefix WHERE subnet_usable_prefix.branch_eni_id = branch_enis.id) > 0
     AND state = 'attached') valid_branch_enis
WHERE c = 0
ORDER BY RANDOM()
LIMIT 1`, subnet, trunkENI)
	} else {
		row = tx.QueryRowContext(ctx, `
SELECT valid_branch_enis.id,
       valid_branch_enis.branch_eni,
       valid_branch_enis.association_id,
       valid_branch_enis.az,
       valid_branch_enis.account_id,
       valid_branch_enis.idx
FROM
  (SELECT branch_enis.id,
          branch_enis.branch_eni,
          branch_enis.az,
          branch_enis.account_id,
          branch_eni_attachments.idx,
          branch_eni_attachments.association_id,
          branch_eni_attachments.created_at AS branch_eni_attached_at,
     (SELECT count(*)
      FROM assignments
      WHERE assignments.branch_eni_association = branch_eni_attachments.association_id) AS c
   FROM branch_enis
   JOIN branch_eni_attachments ON branch_enis.branch_eni = branch_eni_attachments.branch_eni
   WHERE subnet_id = $1
     AND trunk_eni = $2
     AND (SELECT count(*) FROM subnet_usable_prefix WHERE subnet_usable_prefix.branch_eni_id = branch_enis.id) > 0
     AND state = 'attached') valid_branch_enis
WHERE c = 0
ORDER BY c DESC, branch_eni_attached_at ASC
LIMIT 1`, subnet, trunkENI)
	}
	err := row.Scan(&branchENI.ID, &branchENI.BranchENI, &branchENI.AssociationID, &branchENI.AZ, &branchENI.AccountID, &branchENI.Idx)

	if err != nil {
		return nil, err
	}
	return branchENI, nil
}
