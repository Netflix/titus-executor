package node

const (
	TaintKeyBackend             = "node.titus.netflix.com/backend"
	TaintKeyFarzone             = "node.titus.netflix.com/farzone"
	TaintKeyGPUNode             = "node.titus.netflix.com/gpu"
	TaintKeyInit                = "node.titus.netflix.com/uninitialized"
	TaintKeyNodeEvacuate        = "taint.titus.netflix.com/evacuate"
	TaintKeyNodeProblem         = "taint.titus.netflix.com/nodeProblem"
	TaintKeyScheduler           = "node.titus.netflix.com/scheduler"
	TaintKeyTier                = "node.titus.netflix.com/tier"
	TaintKeyNodeDecommissioning = "node.titus.netflix.com/decommissioning"
	TaintKeyNodeScalingDown     = "node.titus.netflix.com/scaling-down"
)
