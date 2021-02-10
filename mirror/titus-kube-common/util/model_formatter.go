package kube

// Data structures and functions for pretty formatting resource pools, nodes, pods, machine types, etc.

import (
	"time"

	poolV1 "github.com/Netflix/titus-controllers-api/api/resourcepool/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/json"
)

const (
	FormatCompact    FormatDetailsLevel = 0
	FormatEssentials FormatDetailsLevel = 1
	FormatDetails    FormatDetailsLevel = 2
)

type FormatDetailsLevel int

type FormatterOptions struct {
	Level FormatDetailsLevel
}

func FormatResourcePool(resourcePool *poolV1.ResourcePoolConfig, options FormatterOptions) string {
	if options.Level == FormatCompact {
		return formatResourcePoolCompact(resourcePool)
	} else if options.Level == FormatEssentials {
		return formatResourcePoolEssentials(resourcePool)
	} else if options.Level == FormatDetails {
		return ToJSONString(resourcePool)
	}
	return formatResourcePoolCompact(resourcePool)
}

func FormatMachineType(machineType *poolV1.MachineTypeConfig, options FormatterOptions) string {
	if options.Level != FormatDetails {
		return formatMachineTypeCompact(machineType)
	}
	return ToJSONString(machineType)
}

func FormatNode(node *v1.Node, ageThreshold time.Duration, options FormatterOptions) string {
	if options.Level == FormatCompact {
		return formatNodeCompact(node, ageThreshold)
	} else if options.Level == FormatEssentials {
		return formatNodeEssentials(node, ageThreshold)
	} else if options.Level == FormatDetails {
		return ToJSONString(node)
	}
	return formatNodeCompact(node, ageThreshold)
}

func FormatPod(pod *v1.Pod, options FormatterOptions) string {
	if options.Level == FormatCompact {
		return formatPodCompact(pod)
	} else if options.Level == FormatEssentials {
		return formatPodEssentials(pod)
	} else if options.Level == FormatDetails {
		return ToJSONString(pod)
	}
	return formatPodCompact(pod)
}

func formatResourcePoolCompact(pool *poolV1.ResourcePoolConfig) string {
	type Compact struct {
		Name               string
		ResourceCount      int64
		AutoScalingEnabled bool
	}
	value := Compact{
		Name:               pool.Name,
		ResourceCount:      pool.Spec.ResourceCount,
		AutoScalingEnabled: pool.Spec.ScalingRules.AutoScalingEnabled,
	}
	return ToJSONString(value)
}

func formatResourcePoolEssentials(pool *poolV1.ResourcePoolConfig) string {
	type Essentials struct {
		Name               string
		ResourceCount      int64
		ResourceShape      poolV1.ComputeResource
		AutoScalingEnabled bool
	}
	value := Essentials{
		Name:               pool.Name,
		ResourceCount:      pool.Spec.ResourceCount,
		ResourceShape:      pool.Spec.ResourceShape.ComputeResource,
		AutoScalingEnabled: pool.Spec.ScalingRules.AutoScalingEnabled,
	}
	return ToJSONString(value)
}

func formatMachineTypeCompact(machineType *poolV1.MachineTypeConfig) string {
	type Compact struct {
		Name            string
		ComputeResource poolV1.ComputeResource
	}
	value := Compact{
		Name:            machineType.Name,
		ComputeResource: machineType.Spec.ComputeResource,
	}
	return ToJSONString(value)
}

func formatNodeCompact(node *v1.Node, ageThreshold time.Duration) string {
	type Compact struct {
		Name     string
		Up       bool
		OnWayOut bool
	}
	value := Compact{
		Name:     node.Name,
		Up:       IsNodeAvailableForScheduling(node, time.Now(), ageThreshold),
		OnWayOut: IsNodeOnItsWayOut(node),
	}
	return ToJSONString(value)
}

func formatNodeEssentials(node *v1.Node, ageThreshold time.Duration) string {
	type Compact struct {
		Name               string
		Up                 bool
		OnWayOut           bool
		AvailableResources poolV1.ComputeResource
	}
	value := Compact{
		Name:               node.Name,
		Up:                 IsNodeAvailableForScheduling(node, time.Now(), ageThreshold),
		OnWayOut:           IsNodeOnItsWayOut(node),
		AvailableResources: FromNodeToComputeResource(node),
	}
	return ToJSONString(value)
}

func formatPodCompact(pod *v1.Pod) string {
	type Compact struct {
		Name  string
		State string
		Node  string
	}
	value := Compact{
		Name:  pod.Name,
		State: toPodState(pod),
		Node:  pod.Spec.NodeName,
	}
	return ToJSONString(value)
}

func formatPodEssentials(pod *v1.Pod) string {
	type Compact struct {
		Name             string
		State            string
		Node             string
		ComputeResources poolV1.ComputeResource
	}
	value := Compact{
		Name:             pod.Name,
		State:            toPodState(pod),
		Node:             pod.Spec.NodeName,
		ComputeResources: FromPodToComputeResource(pod),
	}
	return ToJSONString(value)
}

func toPodState(pod *v1.Pod) string {
	if IsPodRunning(pod) {
		return "running"
	}
	if IsPodFinished(pod) {
		return "finished"
	}
	return "notScheduled"
}

func ToJSONString(value interface{}) string {
	bytes, err := json.Marshal(value)
	if err != nil {
		return "<formatting error>"
	}
	return string(bytes)
}
