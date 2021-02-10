package kube

import (
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"

	commonNode "github.com/Netflix/titus-kube-common/node"
)

func ButPodName(pod *v1.Pod, name string) *v1.Pod {
	pod.Name = name
	return pod
}

func ButPodResourcePools(pod *v1.Pod, resourcePools ...string) *v1.Pod {
	pod.Labels[commonNode.LabelKeyResourcePool] = strings.Join(resourcePools, ",")
	return pod
}

func ButPodAssignedToNode(pod *v1.Pod, node *v1.Node) *v1.Pod {
	pod.Spec.NodeName = node.Name
	return pod
}

func ButPodRunningOnNode(pod *v1.Pod, node *v1.Node) *v1.Pod {
	pod = ButPodAssignedToNode(pod, node)
	pod.Status.Phase = v1.PodRunning
	return pod
}

func ButNodeCreatedTimestamp(node *v1.Node, timestamp time.Time) *v1.Node {
	node.ObjectMeta.CreationTimestamp = v12.Time{Time: timestamp}
	return node
}

func ButNodeWithTaint(node *v1.Node, taint *v1.Taint) *v1.Node {
	node.Spec.Taints = append(node.Spec.Taints, *taint)
	return node
}

func ButNodeDecommissioned(source string, node *v1.Node) *v1.Node {
	return ButNodeWithTaint(node, NewDecommissioningTaint(source, time.Now()))
}

func ButNodeScalingDown(source string, node *v1.Node) *v1.Node {
	return ButNodeWithTaint(node, NewScalingDownTaint(source, time.Now()))
}

func ButNodeRemovable(node *v1.Node) *v1.Node {
	node.Labels[commonNode.LabelKeyRemovable] = True
	return node
}

func NewDecommissioningTaint(source string, now time.Time) *v1.Taint {
	return &v1.Taint{
		Key:       commonNode.TaintKeyNodeDecommissioning,
		Value:     source,
		Effect:    "NoExecute",
		TimeAdded: &metav1.Time{Time: now},
	}
}

func NewScalingDownTaintWithValue(now time.Time, value string) *v1.Taint {
	return &v1.Taint{
		Key:       commonNode.TaintKeyNodeScalingDown,
		Value:     value,
		Effect:    "NoExecute",
		TimeAdded: &v12.Time{Time: now},
	}
}

func NewScalingDownTaint(source string, now time.Time) *v1.Taint {
	return NewScalingDownTaintWithValue(now, source)
}
