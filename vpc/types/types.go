package types

import (
	"errors"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
)

// Allocation is the public interface exposed when we allocate a namespace
type Allocation struct {
	IPV4Address     *vpcapi.UsableAddress `json:"ipv4Address"`
	IPV6Address     *vpcapi.UsableAddress `json:"ipv6Address"`
	DeviceIndex     int                   `json:"deviceIndex"`
	Success         bool                  `json:"success"`
	Error           string                `json:"error"`
	BranchENIID     string                `json:"branchENIID"`
	BranchENIVPC    string                `json:"branchVPCID"`
	BranchENIMAC    string                `json:"branchMAC"`
	VlanID          int                   `json:"vlanID"`
	TrunkENIID      string                `json:"trunkENIID"`
	TrunkENIVPC     string                `json:"trunkVPCID"`
	TrunkENIMAC     string                `json:"trunkMAC"`
	AllocationIndex uint16                `json:"allocationIndex"`
}

// WiringStatus indicates whether or not wiring was successful
type WiringStatus struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// ErrUnsupported indicates that the operation is unsupported on this platform
var ErrUnsupported = errors.New("Unsupported")

// Allocation is the public interface exposed when we allocate a namespace
type LegacyAllocation struct {
	IPV4Address *vpcapi.UsableAddress `json:"ipv4Address"`
	IPV6Address *vpcapi.UsableAddress `json:"ipv6Address"`
	DeviceIndex int                   `json:"deviceIndex"`
	Success     bool                  `json:"success"`
	Error       string                `json:"error"`
	ENI         string                `json:"eni"`
	VPC         string                `json:"vpc"`
	MAC         string                `json:"mac"`
}

type HybridAllocation struct {
	IPV4Address     *vpcapi.UsableAddress `json:"ipv4Address"`
	IPV6Address     *vpcapi.UsableAddress `json:"ipv6Address"`
	DeviceIndex     int                   `json:"deviceIndex"`
	Success         bool                  `json:"success"`
	Error           string                `json:"error"`
	BranchENIID     string                `json:"branchENIID"`
	BranchENIVPC    string                `json:"branchVPCID"`
	BranchENIMAC    string                `json:"branchMAC"`
	VlanID          int                   `json:"vlanID"`
	TrunkENIID      string                `json:"trunkENIID"`
	TrunkENIVPC     string                `json:"trunkVPCID"`
	TrunkENIMAC     string                `json:"trunkMAC"`
	AllocationIndex uint16                `json:"allocationIndex"`
	ENI             string                `json:"eni"`
	VPC             string                `json:"vpc"`
	MAC             string                `json:"mac"`
}
