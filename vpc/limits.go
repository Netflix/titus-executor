package vpc // nolint:dupl

import (
	"fmt"
)

type limits struct {
	interfaces              int
	ipAddressesPerInterface int
	// in Mbps
	networkThroughput int
	branchENIs        int
}

// This function will panic if the instance type is unknown
func getLimits(instanceType string) (limits, error) {
	l, ok := interfaceLimits[instanceType]
	if !ok {
		return limits{}, fmt.Errorf("Unknown instance type: %q", instanceType)
	}
	return l, nil
}

func mustGetLimits(instanceType string) limits {
	l, err := getLimits(instanceType)
	if err != nil {
		panic(err.Error())
	}
	return l
}

// GetMaxInterfaces returns the maximum number of interfaces that this instance type can handle
// includes the primary ENI
func GetMaxInterfaces(instanceType string) (int, error) {
	l, err := getLimits(instanceType)
	return l.interfaces, err
}

// GetMaxIPAddresses returns  the maximum number of IPv4 addresses that this instance type can handle
func GetMaxIPAddresses(instanceType string) (int, error) {
	l, err := getLimits(instanceType)
	return l.ipAddressesPerInterface, err
}

// GetMaxNetworkMbps returns the maximum network throughput in Megabits per second that this instance type can handle
func GetMaxNetworkMbps(instanceType string) (int, error) {
	l, err := getLimits(instanceType)
	return l.networkThroughput, err
}

// GetMaxNetworkbps returns the maximum network throughput in bits per second that this instance type can handle
func GetMaxNetworkbps(instanceType string) (uint64, error) {
	maxNetworkMbps, err := GetMaxNetworkMbps(instanceType)
	return uint64(maxNetworkMbps) * 1000 * 1000, err
}

func GetMaxBranchENIs(instanceType string) (int, error) {
	l, err := getLimits(instanceType)
	if err != nil {
		return 0, err
	}
	if l.branchENIs == 0 {
		return 0, fmt.Errorf("Instance type %s does not support branch ENIs", instanceType)
	}
	return l.branchENIs, nil
}

func MustGetMaxBranchENIs(instanceType string) int {
	l, err := GetMaxBranchENIs(instanceType)
	if err != nil {
		panic(err)
	}
	return l
}

// MustGetMaxInterfaces returns the maximum number of interfaces that this instance type can handle
// includes the primary ENI
func MustGetMaxInterfaces(instanceType string) int {
	return mustGetLimits(instanceType).interfaces
}

// MustGetMaxIPAddresses returns  the maximum number of IPv4 addresses that this instance type can handle
func MustGetMaxIPAddresses(instanceType string) int {
	return mustGetLimits(instanceType).ipAddressesPerInterface
}

// GetMaxNetworkMbps returns the maximum network throughput in Megabits per second that this instance type can handle
func MustGetMaxNetworkMbps(instanceType string) int {
	return mustGetLimits(instanceType).networkThroughput
}

// GetMaxNetworkbps returns the maximum network throughput in bits per second that this instance type can handle
func MustGetMaxNetworkbps(instanceType string) uint64 {
	return uint64(MustGetMaxNetworkMbps(instanceType)) * 1000 * 1000
}
