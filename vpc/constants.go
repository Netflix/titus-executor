package vpc

import "time"

const (
	// RefreshInterval indicates how often an IP holder indicates that it holds it.
	RefreshInterval = 30 * time.Second
	// DefaultMinIdlePeriod is the minimum amount of time an IP must be idle before we consider it for GC
	DefaultMinIdlePeriod = 90 * time.Second
	// IngressIFB is the intermediate functional block device used to do ingress processing
	IngressIFB = "ifb-ingress"
	// EgressIFB is the intermediate functional block device used to do egress processing
	EgressIFB = "ifb-egress"
	// NetworkInterfaceDescription is what interfaces are named
	NetworkInterfaceDescription              = "titus-managed"
	DefaultTrunkNetworkInterfaceDescription  = "titus-managed-trunk"
	DefaultBranchNetworkInterfaceDescription = "titus-managed-branch"
	DefaultSubnetCIDRReservationDescription  = "titus-reserved"
)
