package kube

import (
	"fmt"
	"time"

	"github.com/Netflix/titus-kube-common/node"

	"github.com/google/uuid"

	v13 "k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/Netflix/titus-controllers-api/api/resourcepool/v1"
)

const (
	// TODO Use different resource pool name in tests
	ResourcePoolElastic = "elastic"
)

func NewResourcePoolCrdOf(name string, shapeDimensions v1.ComputeResource, shapeCount int64) *v1.ResourcePoolConfig {
	return &v1.ResourcePoolConfig{
		ObjectMeta: v12.ObjectMeta{
			Name:      name,
			Namespace: "default",
		},
		Spec: v1.ResourcePoolSpec{
			Name: name,
			ResourceShape: v1.ResourceShape{
				ComputeResource: shapeDimensions,
			},
			ScalingRules: v1.ResourcePoolScalingRules{
				MinIdle:            0,
				MaxIdle:            2,
				MinSize:            0,
				MaxSize:            10,
				AutoScalingEnabled: true,
			},
			ResourceCount: shapeCount,
			Status:        v1.ResourceDemandStatus{},
		},
	}
}

func NewResourcePoolCrdOfMachine(name string, machineTypeConfig *v1.MachineTypeConfig, partsCount int64,
	shapeCount int64) *v1.ResourcePoolConfig {
	shapeDimensions := machineTypeConfig.Spec.ComputeResource.Divide(partsCount)
	return NewResourcePoolCrdOf(name, shapeDimensions, shapeCount)
}

func NewNotScheduledPodWithName(name string, resourcePoolName string, resources v1.ComputeResource,
	now time.Time) *v13.Pod {
	return &v13.Pod{
		ObjectMeta: v12.ObjectMeta{
			Name:      name,
			Namespace: "default",
			CreationTimestamp: v12.Time{
				Time: now,
			},
			Labels: map[string]string{
				node.LabelKeyResourcePool: resourcePoolName,
			},
		},
		Spec: v13.PodSpec{
			Containers: []v13.Container{
				{
					Name:  "main",
					Image: "some/image:latest",
					Resources: v13.ResourceRequirements{
						Limits:   FromComputeResourceToResourceList(resources),
						Requests: FromComputeResourceToResourceList(resources),
					},
				},
			},
		},
		Status: v13.PodStatus{},
	}
}

func NewNotScheduledPod(resourcePoolName string, resources v1.ComputeResource, now time.Time) *v13.Pod {
	return NewNotScheduledPodWithName(uuid.New().String()+".pod", resourcePoolName, resources, now)
}

func NewRandomNotScheduledPod() *v13.Pod {
	return NewNotScheduledPod(ResourcePoolElastic, R5Metal().Spec.ComputeResource.Divide(4), time.Now())
}

func NewNotScheduledPods(count int64, namePrefix string, resourcePoolName string, resources v1.ComputeResource,
	now time.Time) []*v13.Pod {
	var pods []*v13.Pod
	for i := int64(0); i < count; i++ {
		pods = append(pods, NewNotScheduledPodWithName(fmt.Sprintf("%v#%v", namePrefix, i), resourcePoolName,
			resources, now))
	}
	return pods
}

func NewNode(name string, resourcePoolName string, machineTypeConfig *v1.MachineTypeConfig) *v13.Node {
	return &v13.Node{
		ObjectMeta: v12.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				node.LabelKeyResourcePool: resourcePoolName,
			},
		},
		Status: v13.NodeStatus{
			Allocatable: FromComputeResourceToResourceList(machineTypeConfig.Spec.ComputeResource),
			Capacity:    FromComputeResourceToResourceList(machineTypeConfig.Spec.ComputeResource),
		},
	}
}

func NewRandomNode(transformers ...func(node *v13.Node)) *v13.Node {
	node := NewNode(uuid.New().String()+".node", ResourcePoolElastic, R5Metal())
	for _, transformer := range transformers {
		transformer(node)
	}
	return node
}

func NewNodes(count int64, namePrefix string, resourcePoolName string,
	machineTypeConfig *v1.MachineTypeConfig) []*v13.Node {
	var nodes []*v13.Node
	for i := int64(0); i < count; i++ {
		nodes = append(nodes, NewNode(fmt.Sprintf("%v-%v", namePrefix, i), resourcePoolName,
			machineTypeConfig))
	}
	return nodes
}
