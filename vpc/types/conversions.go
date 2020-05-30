package types

import vpcapi "github.com/Netflix/titus-executor/vpc/api"

func AssignmentToAllocation(assignment *vpcapi.AssignIPResponseV3) Allocation {
	alloc := Allocation{
		Success:         true,
		BranchENIID:     assignment.BranchNetworkInterface.NetworkInterfaceId,
		BranchENIMAC:    assignment.BranchNetworkInterface.MacAddress,
		BranchENIVPC:    assignment.BranchNetworkInterface.VpcId,
		BranchENISubnet: assignment.BranchNetworkInterface.SubnetId,
		VlanID:          int(assignment.VlanId),
		TrunkENIID:      assignment.TrunkNetworkInterface.NetworkInterfaceId,
		TrunkENIMAC:     assignment.TrunkNetworkInterface.MacAddress,
		TrunkENIVPC:     assignment.TrunkNetworkInterface.VpcId,
		AllocationIndex: uint16(assignment.ClassId),
		DeviceIndex:     int(assignment.VlanId),
		Generation:      GenerationPointer(V3),
	}

	if assignment.Ipv6Address != nil {
		alloc.IPV6Address = assignment.Ipv6Address
	}

	if assignment.Ipv4Address != nil {
		alloc.IPV4Address = assignment.Ipv4Address
	}

	return alloc
}
