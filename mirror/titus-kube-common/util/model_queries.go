package kube

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	v12 "github.com/Netflix/titus-controllers-api/api/resourcepool/v1"

	nodeCommon "github.com/Netflix/titus-kube-common/node"
)

type NodeAndPods struct {
	Node *v1.Node
	Pods []*v1.Pod
}

func NodeAge(node *v1.Node, now time.Time) time.Duration {
	return now.Sub(node.CreationTimestamp.Time)
}

func PodAge(pod *v1.Pod, now time.Time) time.Duration {
	return now.Sub(pod.CreationTimestamp.Time)
}

// FIXME Resources are in MB but should be in bytes
func FromResourceListToComputeResource(limits v1.ResourceList) v12.ComputeResource {
	result := v12.ComputeResource{
		CPU:      limits.Cpu().Value(),
		MemoryMB: limits.Memory().Value() / OneMegaByte,
		DiskMB:   limits.StorageEphemeral().Value() / OneMegaByte,
	}
	if gpu, ok := limits[ResourceGpu]; ok {
		result.GPU += gpu.Value()
	}
	if network, ok := limits[ResourceNetwork]; ok {
		result.NetworkMBPS += network.Value() / OneMBPS
	}
	return result
}

func FromComputeResourceToResourceList(resources v12.ComputeResource) v1.ResourceList {
	return v1.ResourceList{
		v1.ResourceCPU:              resource.MustParse(strconv.FormatInt(resources.CPU, 10)),
		v1.ResourceMemory:           resource.MustParse(fmt.Sprintf("%vMi", resources.MemoryMB)),
		v1.ResourceEphemeralStorage: resource.MustParse(fmt.Sprintf("%vMi", resources.DiskMB)),
		ResourceGpu:                 resource.MustParse(strconv.FormatInt(resources.GPU, 10)),
		ResourceNetwork:             resource.MustParse(fmt.Sprintf("%vM", resources.NetworkMBPS)),
	}
}

func FromPodToComputeResource(pod *v1.Pod) v12.ComputeResource {
	total := v12.ComputeResource{}
	for _, container := range pod.Spec.Containers {
		total = total.Add(FromResourceListToComputeResource(container.Resources.Requests))
	}
	return total
}

func FromNodeToComputeResource(node *v1.Node) v12.ComputeResource {
	return FromResourceListToComputeResource(node.Status.Allocatable)
}

func NodeNames(nodes []*v1.Node) []string {
	var names []string
	for _, node := range nodes {
		names = append(names, node.Name)
	}
	return names
}

func PodNames(pods *[]v1.Pod) []string {
	var names []string
	for _, node := range *pods {
		names = append(names, node.Name)
	}
	return names
}

func FindLabel(labels map[string]string, labelName string) (string, bool) {
	if labels == nil {
		return "", false
	}
	if actual, ok := labels[labelName]; ok {
		return actual, true
	}
	return "", false
}

func FindTaint(node *v1.Node, taintKey string) *v1.Taint {
	for _, taint := range node.Spec.Taints {
		if taint.Key == taintKey {
			return &taint
		}
	}
	return nil
}

// A pod may be assigned to multiple resource pools. The first one returned is considered the primary which will
// be scaled up if more capacity is needed.
func FindPodAssignedResourcePools(pod *v1.Pod) ([]string, bool) {
	var poolNames string
	var ok bool
	if poolNames, ok = FindLabel(pod.Labels, nodeCommon.LabelKeyResourcePool); !ok {
		if poolNames, ok = FindLabel(pod.Annotations, nodeCommon.LabelKeyResourcePool); !ok {
			return []string{}, false
		}
	}
	if poolNames == "" {
		return []string{}, false
	}
	parts := strings.Split(poolNames, ",")
	var names []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if len(trimmed) > 0 {
			names = append(names, trimmed)
		}
	}
	if len(names) == 0 {
		return []string{}, false
	}
	return names, true
}

func FindPodPrimaryResourcePool(pod *v1.Pod) (string, bool) {
	if poolNames, ok := FindPodAssignedResourcePools(pod); ok {
		return poolNames[0], true
	}
	return "", false
}

// Find all pods for which the given resource pool is primary.
func FindPodsWithPrimaryResourcePool(resourcePool string, pods []*v1.Pod) []*v1.Pod {
	var result []*v1.Pod
	for _, pod := range pods {
		if primary, ok := FindPodPrimaryResourcePool(pod); ok {
			if primary == resourcePool {
				result = append(result, pod)
			}
		}
	}
	return result
}

func FindNotScheduledPods(pods []*v1.Pod) []*v1.Pod {
	var waiting []*v1.Pod
	for _, pod := range pods {
		if IsPodWaitingToBeScheduled(pod) {
			waiting = append(waiting, pod)
		}
	}
	return waiting
}

// Find all unscheduled pods belonging to the given resource pool, which are not younger than a threshold.
func FindOldNotScheduledPods(pods []*v1.Pod, youngPodThreshold time.Duration, now time.Time) []*v1.Pod {
	var waiting []*v1.Pod
	for _, pod := range pods {
		if IsPodWaitingToBeScheduled(pod) && PodAge(pod, now) >= youngPodThreshold {
			waiting = append(waiting, pod)
		}
	}
	return waiting
}

// For a given resource pool:
// 1. find its all nodes and pods
// 2. map pods to their nodes
// 3. collect pods not running on any node in a separate list
func GroupNodesAndPods(resourcePool *v12.ResourcePoolSpec, allPods []*v1.Pod,
	allNodes []*v1.Node) (map[string]NodeAndPods, []*v1.Pod) {
	var nodesAndPodsMap = map[string]NodeAndPods{}
	var podsWithoutNode []*v1.Pod

	for _, node := range allNodes {
		if NodeBelongsToResourcePool(node, resourcePool) {
			nodesAndPodsMap[node.Name] = NodeAndPods{Node: node}
		}
	}
	for _, pod := range allPods {
		// Do not include finished pods
		if pod.Status.Phase != "Succeeded" && pod.Status.Phase != "Failed" {
			// We do not check if a pod is directly associated with the resource pool, as we only care
			// that it runs on a node that belongs to it.
			if nodeAndPods, ok := nodesAndPodsMap[pod.Spec.NodeName]; ok {
				nodeAndPods.Pods = append(nodeAndPods.Pods, pod)
				nodesAndPodsMap[pod.Spec.NodeName] = nodeAndPods
			} else {
				podsWithoutNode = append(podsWithoutNode, pod)
			}
		}
	}
	return nodesAndPodsMap, podsWithoutNode
}

// Sort in place an array of nodes by the creation timestamp.
func SortNodesByAge(nodes []*v1.Node) []*v1.Node {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].CreationTimestamp.Before(&nodes[j].CreationTimestamp)
	})
	return nodes
}

func FilterRunningPods(pods []*v1.Pod) []*v1.Pod {
	var active []*v1.Pod
	for _, pod := range pods {
		if IsPodRunning(pod) {
			active = append(active, pod)
		}
	}
	return active
}

func CountNotScheduledPods(pods []*v1.Pod) int64 {
	var count int64
	for _, pod := range pods {
		if IsPodWaitingToBeScheduled(pod) {
			count = count + 1
		}
	}
	return count
}

func SumNodeResources(nodes []*v1.Node) v12.ComputeResource {
	var sum v12.ComputeResource
	for _, node := range nodes {
		sum = sum.Add(FromNodeToComputeResource(node))
	}
	return sum
}

func SumPodResources(pods []*v1.Pod) v12.ComputeResource {
	var sum v12.ComputeResource
	for _, pod := range pods {
		sum = sum.Add(FromPodToComputeResource(pod))
	}
	return sum
}
