package kube

import (
	"time"

	v1 "k8s.io/api/core/v1"

	v12 "github.com/Netflix/titus-controllers-api/api/resourcepool/v1"

	nodeCommon "github.com/Netflix/titus-kube-common/node"
)

func HasLabelAndValue(labels map[string]string, labelName string, value string) bool {
	if actual, ok := FindLabel(labels, labelName); ok {
		return value == actual
	}
	return false
}

func HasNoExecuteTaint(node *v1.Node) bool {
	for _, taint := range node.Spec.Taints {
		if taint.Effect == "NoExecute" {
			return true
		}
	}
	return false
}

func IsPodWaitingToBeScheduled(pod *v1.Pod) bool {
	return pod.Spec.NodeName == "" && !IsPodFinished(pod)
}

func IsPodRunning(pod *v1.Pod) bool {
	if IsPodFinished(pod) {
		return false
	}
	return pod.Spec.NodeName != ""
}

func IsPodFinished(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodSucceeded || pod.Status.Phase == v1.PodFailed
}

// Returns true for a new node that is still bootstrapping. `ageThreshold` is a time limit for a node to be
// regarded as new.
func IsNodeBootstrapping(node *v1.Node, now time.Time, ageThreshold time.Duration) bool {
	// This taint explicitly tells us that the node is initializing.
	if FindTaint(node, nodeCommon.TaintKeyInit) != nil {
		return true
	}

	if node.CreationTimestamp.Add(ageThreshold).Before(now) {
		return false
	}

	// Getting here does not guarantee (at least at the time of writing this change), that the new node is
	// fully initialized and ready to take traffic. We make here a few heuristic guesses to improve th evaluation
	// accuracy.
	return IsNodeBroken(node)
}

func IsNodeBroken(node *v1.Node) bool {
	// FIXME Discern better between actual bad states and other cases
	if HasNoExecuteTaint(node) {
		return true
	}

	// It happens that there are node objects registered with no resources
	if node.Status.Allocatable.Cpu().IsZero() {
		return true
	}

	return false
}

func IsNodeAvailableForScheduling(node *v1.Node, now time.Time, ageThreshold time.Duration) bool {
	return !IsNodeBootstrapping(node, now, ageThreshold) &&
		!IsNodeToRemove(node) &&
		!IsNodeRemovable(node) &&
		!IsNodeTerminated(node)
}

func IsNodeOnItsWayOut(node *v1.Node) bool {
	return IsNodeToRemove(node) || IsNodeRemovable(node) || IsNodeTerminated(node)
}

func IsNodeDecommissioned(node *v1.Node) bool {
	return FindTaint(node, nodeCommon.TaintKeyNodeDecommissioning) != nil
}

func IsNodeScalingDown(node *v1.Node) bool {
	return FindTaint(node, nodeCommon.TaintKeyNodeScalingDown) != nil
}

func IsNodeToRemove(node *v1.Node) bool {
	return IsNodeDecommissioned(node) || IsNodeScalingDown(node)
}

func IsNodeRemovable(node *v1.Node) bool {
	_, ok := FindLabel(node.Labels, nodeCommon.LabelKeyRemovable)
	return ok
}

// TODO There is no obvious way to determine if a node object corresponds to an existing node instance.
// We trust here that node GC or node graceful shutdown deal with it quickly enough.
func IsNodeTerminated(node *v1.Node) bool {
	return false
}

func PodBelongsToResourcePool(pod *v1.Pod, resourcePool *v12.ResourcePoolSpec, nodes []*v1.Node) bool {
	// Do not look at pods requesting GPU resources, but running in non-GPU resource pool.
	if resourcePool.ResourceShape.GPU <= 0 {
		for _, container := range pod.Spec.Containers {
			if FromResourceListToComputeResource(container.Resources.Requests).GPU > 0 {
				return false
			}
		}
	}
	assignedPools, ok := FindPodAssignedResourcePools(pod)
	if !ok {
		return false
	}

	for _, pool := range assignedPools {
		if pool == resourcePool.Name {
			// If the pod is not assigned to any node, we stop at this point.
			if pod.Spec.NodeName == "" {
				return true
			}
			// If the pod is assigned to a node, we check that the node itself belongs to the same resource pool.
			for _, node := range nodes {
				if NodeBelongsToResourcePool(node, resourcePool) && node.Name == pod.Spec.NodeName {
					return true
				}
			}
			return false
		}
	}

	return false
}

func NodeBelongsToResourcePool(node *v1.Node, resourcePool *v12.ResourcePoolSpec) bool {
	return HasLabelAndValue(node.Labels, nodeCommon.LabelKeyResourcePool, resourcePool.Name)
}
