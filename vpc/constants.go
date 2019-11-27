package vpc

const (
	// IngressIFB is the intermediate functional block device used to do ingress processing
	IngressIFB = "ifb-ingress"
	// EgressIFB is the intermediate functional block device used to do egress processing
	EgressIFB = "ifb-egress"
	// NetworkInterfaceDescription is what interfaces are named
	NetworkInterfaceDescription = "titus-managed"
	// ENICreationTimeTag is an EC2 tag that indicates when this network interface was created (in RFC3339 time)
	ENICreationTimeTag                = "eni-creation-time"
	TrunkNetworkInterfaceDescription  = "titus-managed-trunk"
	BranchNetworkInterfaceDescription = "titus-managed-branch"
)
