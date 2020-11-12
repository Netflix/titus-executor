package pod

const (
	// Networking
	AnnotationKeyEgressBandwidth  = "kubernetes.io/egress-bandwidth"
	AnnotationKeyIngressBandwidth = "kubernetes.io/ingress-bandwidth"

	// Security
	AnnotationKeyIAMRole        = "iam.amazonaws.com/role"
	AnnotationKeySecurityGroups = "network.titus.netflix.com/securityGroups"
)
