package types

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
)

const (
	SecurityGroupsAnnotation   = "network.titus.netflix.com/securityGroups"
	IngressBandwidthAnnotation = "kubernetes.io/ingress-bandwidth"
	EgressBandwidthAnnotation  = "kubernetes.io/egress-bandwidth"
)

type Generation string

const (
	V1 Generation = "v1"
	V3 Generation = "v3"
)

var (
	v1 = V1
	v3 = V3
)

func (s Generation) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(string(s))
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func (s *Generation) UnmarshalJSON(b []byte) error {
	var str string
	err := json.Unmarshal(b, &str)
	if err != nil {
		return err
	}
	switch str {
	case "v1", "v3":
		*s = Generation(str)
		return nil
	default:
		return fmt.Errorf("Unknown vpc generation %q", str)
	}
}

func GenerationPointer(g Generation) *Generation {
	switch g {
	case V1:
		return &v1
	case V3:
		return &v3
	default:
		panic(fmt.Sprintf("Unknown generation %s", string(g)))
	}
}

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
	BranchENISubnet string                `json:"branchENISubnetID"`
	VlanID          int                   `json:"vlanID"`
	TrunkENIID      string                `json:"trunkENIID"`
	TrunkENIVPC     string                `json:"trunkVPCID"`
	TrunkENIMAC     string                `json:"trunkMAC"`
	AllocationIndex uint16                `json:"allocationIndex"`
	Generation      *Generation           `json:"generation"`
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
	Generation  *Generation           `json:"generation"`
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
	BranchENISubnet string                `json:"branchENISubnetID"`
	VlanID          int                   `json:"vlanID"`
	TrunkENIID      string                `json:"trunkENIID"`
	TrunkENIVPC     string                `json:"trunkVPCID"`
	TrunkENIMAC     string                `json:"trunkMAC"`
	AllocationIndex uint16                `json:"allocationIndex"`
	ENI             string                `json:"eni"`
	VPC             string                `json:"vpc"`
	MAC             string                `json:"mac"`
	Generation      *Generation           `json:"generation"`
}
