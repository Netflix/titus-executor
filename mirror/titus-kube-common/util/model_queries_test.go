package kube

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	k8sCore "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/Netflix/titus-controllers-api/api/resourcepool/v1"
)

const testPool = "testPool"

func TestGroupNodesAndPods(t *testing.T) {
	resourcePool := NewResourcePoolCrdOfMachine(testPool, R5Metal(), 1, 1).Spec
	allNodes := []*k8sCore.Node{
		NewNode("node1", resourcePool.Name, R5Metal()),
		NewNode("node2", "someOtherResourcePool", R5Metal()),
	}
	allPods := []*k8sCore.Pod{
		ButPodAssignedToNode(NewNotScheduledPod(testPool, ComputeResource{}, time.Now()), allNodes[0]),
		ButPodAssignedToNode(NewNotScheduledPod("otherResourcePoolSameNode", ComputeResource{}, time.Now()), allNodes[0]),
		NewNotScheduledPod(testPool, ComputeResource{}, time.Now()),
	}

	nodeAndPods, otherPods := GroupNodesAndPods(&resourcePool, allPods, allNodes)
	require.EqualValues(t, 1, len(nodeAndPods))
	require.EqualValues(t, "node1", nodeAndPods["node1"].Node.Name)
	require.EqualValues(t, 2, len(nodeAndPods["node1"].Pods))
	require.EqualValues(t, allPods[0].Name, nodeAndPods["node1"].Pods[0].Name)
	require.EqualValues(t, allPods[1].Name, nodeAndPods["node1"].Pods[1].Name)

	require.EqualValues(t, 1, len(otherPods))
	require.EqualValues(t, allPods[2].Name, otherPods[0].Name)
}

func TestSortNodesByAge(t *testing.T) {
	newNodeCreatedAt := func(timestamp time.Time) *k8sCore.Node {
		return NewRandomNode(func(node *k8sCore.Node) { node.CreationTimestamp = metaV1.Time{Time: timestamp} })
	}

	now := time.Now()
	nodes := []*k8sCore.Node{
		newNodeCreatedAt(now.Add(-0 * time.Hour)),
		newNodeCreatedAt(now.Add(-1 * time.Hour)),
		newNodeCreatedAt(now.Add(-3 * time.Hour)),
		newNodeCreatedAt(now.Add(-2 * time.Hour)),
	}
	sorted := SortNodesByAge(nodes)
	require.EqualValues(t, sorted, nodes) // Sorting in place
	require.EqualValues(t, now.Add(-3*time.Hour), sorted[0].CreationTimestamp.Time)
	require.EqualValues(t, now.Add(-2*time.Hour), sorted[1].CreationTimestamp.Time)
	require.EqualValues(t, now.Add(-1*time.Hour), sorted[2].CreationTimestamp.Time)
	require.EqualValues(t, now.Add(-0*time.Hour), sorted[3].CreationTimestamp.Time)
}

func TestFindPodAssignedResourcePools(t *testing.T) {
	pod := ButPodResourcePools(NewRandomNotScheduledPod(), "   poolPrimary  ,   poolSecondary  ")
	found, ok := FindPodAssignedResourcePools(pod)
	require.True(t, ok, "no resource pools found")
	require.True(t, len(found) == 2, "expected two resource pools")
	require.EqualValues(t, found[0], "poolPrimary")
	require.EqualValues(t, found[1], "poolSecondary")
}

func TestFindPodPrimaryResourcePool(t *testing.T) {
	pod := ButPodResourcePools(NewRandomNotScheduledPod(), "   poolPrimary  ,   poolSecondary  ")
	found, ok := FindPodPrimaryResourcePool(pod)
	require.True(t, ok, "no resource pools found")
	require.EqualValues(t, found, "poolPrimary")
}

func TestFindPodsWithPrimaryResourcePool(t *testing.T) {
	pod1 := ButPodResourcePools(NewRandomNotScheduledPod(), "pool1")
	pod2 := ButPodResourcePools(NewRandomNotScheduledPod(), "pool2")

	found := FindPodsWithPrimaryResourcePool("pool1", []*k8sCore.Pod{pod1, pod2})
	require.True(t, len(found) == 1, "expected one pod")
	require.EqualValues(t, found[0].Name, pod1.Name)
}
