package kube

import (
	"testing"

	nodeCommon "github.com/Netflix/titus-kube-common/node"
	"github.com/stretchr/testify/require"
	k8sCore "k8s.io/api/core/v1"
)

func TestNotScheduledPodBelongsToResourcePool(t *testing.T) {
	resourcePool1 := NewResourcePoolCrdOfMachine("pool1", R5Metal(), 1, 1)
	resourcePool2 := NewResourcePoolCrdOfMachine("pool2", R5Metal(), 1, 1)
	resourcePool3 := NewResourcePoolCrdOfMachine("pool3", R5Metal(), 1, 1)

	pod := NewRandomNotScheduledPod()
	pod.Labels[nodeCommon.LabelKeyResourcePool] = "pool1, pool2"

	require.True(t, PodBelongsToResourcePool(pod, &resourcePool1.Spec, nil))
	require.True(t, PodBelongsToResourcePool(pod, &resourcePool2.Spec, nil))
	require.False(t, PodBelongsToResourcePool(pod, &resourcePool3.Spec, nil))
}

func TestScheduledPodBelongsToResourcePool(t *testing.T) {
	resourcePool1 := NewResourcePoolCrdOfMachine("pool1", R5Metal(), 1, 1)
	resourcePool2 := NewResourcePoolCrdOfMachine("pool2", R5Metal(), 1, 1)
	resourcePool3 := NewResourcePoolCrdOfMachine("pool3", R5Metal(), 1, 1)
	node1 := NewNode("node1", "pool1", R5Metal())
	node2 := NewNode("node2", "pool2", R5Metal())
	nodes := []*k8sCore.Node{node1, node2}

	pod := ButPodAssignedToNode(NewRandomNotScheduledPod(), node1)
	pod.Labels[nodeCommon.LabelKeyResourcePool] = "pool1, pool2"

	require.True(t, PodBelongsToResourcePool(pod, &resourcePool1.Spec, nodes))
	require.False(t, PodBelongsToResourcePool(pod, &resourcePool2.Spec, nodes))
	require.False(t, PodBelongsToResourcePool(pod, &resourcePool3.Spec, nodes))
}
