package data

import "database/sql"

type Assignment struct {
	// Row ID of the assignment in the DB table
	ID int
	// For a normal assignment, this will be the task ID.
	AssignmentID string

	// Branch ENI used in this assignment
	BranchENI string
	// Trunk ENI that the branch ENI is attached to
	TrunkENI string
	// ID of the branch ENI and trunk ENI association
	AssociationID string

	// VLAN ID of the branch ENI
	VlanID int

	// IPv4 address assigned to the task
	IPv4Addr sql.NullString
	// IPv6 address assigned to the task
	IPv6Addr sql.NullString
	// Subnet ID that the branch ENI belongs to
	SubnetID sql.NullString

	Jumbo     bool
	Bandwidth uint64
	Ceil      uint64
}
