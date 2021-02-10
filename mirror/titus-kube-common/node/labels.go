package node

const (
	LabelKeyASG             = "node.titus.netflix.com/asg"
	LabelKeyBackend         = "node.titus.netflix.com/backend"
	LabelKeyDecommissioning = "node.titus.netflix.com/decommissioning"
	LabelKeyInstanceID      = "node.titus.netflix.com/id"
	LabelKeyRemovable       = "node.titus.netflix.com/removable"
	LabelKeyResourcePool    = "scaler.titus.netflix.com/resource-pool"
	LabelKeyTerminating     = "node.titus.netflix.com/terminating"
	LabelKeyInstanceType    = "node.kubernetes.io/instance-type"
	LabelKeyMutableBuild    = "node.titus.netflix.com/mutable-build"
)
