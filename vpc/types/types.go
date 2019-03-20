package types

import "errors"

// Allocation is the public interface exposed when we allocate a namespace
type Allocation struct {
	IPV4Address string `json:"ipv4Address"`
	IPV6Address string `json:"ipv6Address"`
	DeviceIndex int    `json:"deviceIndex"`
	Success     bool   `json:"success"`
	Error       string `json:"error"`
	ENI         string `json:"eni"`
	VPC         string `json:"vpc"`
}

// WiringStatus indicates whether or not wiring was successful
type WiringStatus struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

// ErrUnsupported indicates that the operation is unsupported on this platform
var ErrUnsupported = errors.New("Unsupported")
