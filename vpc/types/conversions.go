package types

import (
	"errors"
	"strconv"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	corev1 "k8s.io/api/core/v1"
)

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

func PodToAllocation(pod *corev1.Pod) (Allocation, error) {
	vlanID, err := strconv.ParseUint(pod.Annotations[VlanIDAnnotation], 10, 64)
	if err != nil {
		return Allocation{}, err
	}

	allocationIndex, err := strconv.ParseUint(pod.Annotations[AllocationIdxAnnotation], 10, 16)
	if err != nil {
		return Allocation{}, err
	}

	alloc := Allocation{
		Success:         true,
		BranchENIID:     pod.Annotations[BranchEniIDAnnotation],
		BranchENIMAC:    pod.Annotations[BranchEniMacAnnotation],
		BranchENIVPC:    pod.Annotations[BranchEniVpcAnnotation],
		BranchENISubnet: pod.Annotations[BranchEniSubnetAnnotation],
		VlanID:          int(vlanID),
		TrunkENIID:      pod.Annotations[TrunkEniIDAnnotation],
		TrunkENIMAC:     pod.Annotations[TrunkEniMacAnnotation],
		TrunkENIVPC:     pod.Annotations[TrunkEniVpcAnnotation],
		DeviceIndex:     int(vlanID),
		AllocationIndex: uint16(allocationIndex),
		Generation:      GenerationPointer(V3),
	}

	if addr, ok := pod.Annotations[IPv4AddressAnnotation]; ok {
		lenStr, ok := pod.Annotations[IPv4PrefixLengthAnnotation]
		if !ok {
			return alloc, errors.New(IPv4PrefixLengthAnnotation + " not found on pod")
		}

		len, err := strconv.ParseInt(lenStr, 10, 32)
		if err != nil {
			return alloc, err
		}

		alloc.IPV4Address = &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: addr,
			},
			PrefixLength: uint32(len),
		}
	}

	if addr, ok := pod.Annotations[IPv6AddressAnnotation]; ok {
		lenStr, ok := pod.Annotations[IPv4PrefixLengthAnnotation]
		if !ok {
			return alloc, errors.New(IPv6PrefixLengthAnnotation + " not found on pod")
		}

		len, err := strconv.ParseInt(lenStr, 10, 32)
		if err != nil {
			return alloc, err
		}

		alloc.IPV4Address = &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: addr,
			},
			PrefixLength: uint32(len),
		}
	}

	return alloc, nil
}
