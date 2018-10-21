package vpc

import (
	"fmt"
	"strings"
)

type limits struct {
	interfaces               int
	ipAddressesPerInterface  int
	ip6AddressesPerInterface int
	// in Mbps
	networkThroughput int
}

var interfaceLimits = map[string]map[string]limits{
	"m4": {
		"large": limits{
			interfaces:               2,
			ipAddressesPerInterface:  10,
			ip6AddressesPerInterface: 2,
			networkThroughput:        100,
		},
		"xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"2xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"4xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        2000,
		},
		"10xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			// Is this number correct?
			networkThroughput: 10000,
		},
		"16xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        23000,
		},
	},
	"m5": {
		"large": limits{
			interfaces:               3,
			ipAddressesPerInterface:  10,
			ip6AddressesPerInterface: 2,
			networkThroughput:        100,
		},
		"xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"2xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"4xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        2000,
		},
		"12xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			// Is this number correct?
			networkThroughput: 10000,
		},
		"24xlarge": limits{
			interfaces:               15,
			ipAddressesPerInterface:  50,
			ip6AddressesPerInterface: 2,
			networkThroughput:        23000,
		},
	},
	"r4": {
		"large": limits{
			interfaces:               3,
			ipAddressesPerInterface:  10,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"2xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        2000,
		},
		"4xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        4000,
		},
		"8xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        9000,
		},
		"16xlarge": limits{
			interfaces:               15,
			ipAddressesPerInterface:  24,
			ip6AddressesPerInterface: 2,
			networkThroughput:        23000,
		},
	},
	"r5": {
		"large": limits{
			interfaces:               3,
			ipAddressesPerInterface:  10,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        1000,
		},
		"2xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        2000,
		},
		"4xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        4000,
		},
		"12xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        9000,
		},
		"24xlarge": limits{
			interfaces:               15,
			ipAddressesPerInterface:  50,
			ip6AddressesPerInterface: 2,
			networkThroughput:        23000,
		},
	},
	"p2": {
		"xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			// Maybe?
			networkThroughput: 2000,
		},
		"8xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        6000,
		},
		"16xlarge": limits{
			interfaces:               8,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        20000,
		},
	},
	"c5": {
		"large": limits{
			interfaces:               3,
			ipAddressesPerInterface:  10,
			ip6AddressesPerInterface: 2,
			// Maybe?
			networkThroughput: 1000,
		},
		"xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        2000,
		},
		"2xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  15,
			ip6AddressesPerInterface: 2,
			networkThroughput:        2000,
		},
		"4xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        4000,
		},
		"9xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  30,
			ip6AddressesPerInterface: 2,
			networkThroughput:        10000,
		},
		"18xlarge": limits{
			interfaces:               4,
			ipAddressesPerInterface:  50,
			ip6AddressesPerInterface: 2,
			networkThroughput:        23000,
		},
	},
}

// This function will panic if the instance type is unknown
func getLimits(instanceType string) limits {
	familyAndSubtype := strings.Split(instanceType, ".")
	family := familyAndSubtype[0]
	subtype := familyAndSubtype[1]
	subtypes, ok := interfaceLimits[family]
	if !ok {
		panic(fmt.Sprint("Unknown family: ", family))
	}

	limits, ok := subtypes[subtype]
	if !ok {
		panic(fmt.Sprint("Unknown subtype for family: ", subtype))
	}
	return limits
}

// GetMaxInterfaces returns the maximum number of interfaces that this instance type can handle
// includes the primary ENI
func GetMaxInterfaces(instanceType string) int {
	return getLimits(instanceType).interfaces
}

// GetMaxIPv4Addresses returns  the maximum number of IPv4 addresses that this instance type can handle
func GetMaxIPv4Addresses(instanceType string) int {
	return getLimits(instanceType).ipAddressesPerInterface
}

// GetMaxIPv6Addresses returns  the maximum number of IPv6 addresses that this instance type can handle per interface
func GetMaxIPv6Addresses(instanceType string) int {
	return getLimits(instanceType).ip6AddressesPerInterface
}

// GetMaxNetworkMbps returns the maximum network throughput in Megabits per second that this instance type can handle
func GetMaxNetworkMbps(instanceType string) int {
	return getLimits(instanceType).networkThroughput
}

// GetMaxNetworkbps returns the maximum network throughput in bits per second that this instance type can handle
func GetMaxNetworkbps(instanceType string) uint64 {
	return uint64(GetMaxNetworkMbps(instanceType)) * 1000 * 1000
}
