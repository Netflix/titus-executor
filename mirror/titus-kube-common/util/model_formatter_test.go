package kube

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFormatResourcePoolCompact(t *testing.T) {
	text := FormatResourcePool(
		NewResourcePoolCrdOfMachine("unitTestPool", R5Metal(), 4, 1),
		FormatterOptions{Level: FormatCompact},
	)
	require.EqualValues(t,
		"{\"Name\":\"unitTestPool\",\"ResourceCount\":1,\"AutoScalingEnabled\":true}",
		text,
	)
}

func TestFormatResourcePoolEssentials(t *testing.T) {
	text := FormatResourcePool(
		NewResourcePoolCrdOfMachine("unitTestPool", R5Metal(), 4, 1),
		FormatterOptions{Level: FormatEssentials},
	)
	require.EqualValues(t,
		"{\"Name\":\"unitTestPool\",\"ResourceCount\":1,\"ResourceShape\":{\"cpu\":24,\"gpu\":0,"+
			"\"memoryMB\":196608,\"diskMB\":384000,\"networkMBPS\":6250},\"AutoScalingEnabled\":true}",
		text,
	)
}

func TestFormatMachineTypeCompact(t *testing.T) {
	text := FormatMachineType(
		R5Metal(),
		FormatterOptions{Level: FormatCompact},
	)
	require.EqualValues(t,
		"{\"Name\":\"r5.metal\",\"ComputeResource\":{\"cpu\":96,\"gpu\":0,"+
			"\"memoryMB\":786432,\"diskMB\":1536000,\"networkMBPS\":25000}}",
		text,
	)
}

func TestFormatNodeCompact(t *testing.T) {
	text := FormatNode(
		NewNode("junitNode", "testResourcePool", R5Metal()),
		10*time.Minute,
		FormatterOptions{Level: FormatCompact},
	)
	require.EqualValues(t,
		"{\"Name\":\"junitNode\",\"Up\":true,\"OnWayOut\":false}",
		text,
	)
}

func TestFormatNodeEssentials(t *testing.T) {
	text := FormatNode(
		NewNode("junitNode", "testResourcePool", R5Metal()),
		10*time.Minute,
		FormatterOptions{Level: FormatEssentials},
	)
	require.EqualValues(t,
		"{\"Name\":\"junitNode\",\"Up\":true,\"OnWayOut\":false,\"AvailableResources\":{\"cpu\":96,\"gpu\":0,"+
			"\"memoryMB\":786432,\"diskMB\":1536000,\"networkMBPS\":25000}}",
		text,
	)
}

func TestFormatPodCompact(t *testing.T) {
	text := FormatPod(
		ButPodName(NewRandomNotScheduledPod(), "testPod"),
		FormatterOptions{Level: FormatCompact},
	)
	require.EqualValues(t,
		"{\"Name\":\"testPod\",\"State\":\"notScheduled\",\"Node\":\"\"}",
		text,
	)
}

func TestFormatPodEssentials(t *testing.T) {
	text := FormatPod(
		ButPodRunningOnNode(ButPodName(NewRandomNotScheduledPod(), "testPod"),
			NewNode("junitNode", "testResourcePool", R5Metal())),
		FormatterOptions{Level: FormatEssentials},
	)
	require.EqualValues(t,
		"{\"Name\":\"testPod\",\"State\":\"running\",\"Node\":\"junitNode\","+
			"\"ComputeResources\":{\"cpu\":24,\"gpu\":0,\"memoryMB\":196608,\"diskMB\":384000,\"networkMBPS\":6250}}",
		text,
	)
}
