package types

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	protobuf "github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestImageNameWithTag(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	assert.NoError(t, err)
	expected := "docker.io/titusoss/alpine:latest"
	c := &Container{
		Config: *cfg,
		TitusInfo: &titus.ContainerInfo{
			ImageName: protobuf.String("titusoss/alpine"),
			Version:   protobuf.String("latest"),
		},
	}
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestImageTagLatestByDefault(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	assert.NoError(t, err)

	expected := "docker.io/titusoss/alpine:latest"
	c := &Container{
		Config: *cfg,
		TitusInfo: &titus.ContainerInfo{
			ImageName: protobuf.String("titusoss/alpine"),
		},
	}
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestImageByDigest(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	assert.NoError(t, err)

	expected := "docker.io/" +
		"titusoss/alpine@sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	c := &Container{
		Config: *cfg,
		TitusInfo: &titus.ContainerInfo{
			ImageName:   protobuf.String("titusoss/alpine"),
			ImageDigest: protobuf.String("sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"),
		},
	}
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestImageByDigestIgnoresTag(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	assert.NoError(t, err)

	expected := "docker.io/" +
		"titusoss/alpine@sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	c := &Container{
		Config: *cfg,
		TitusInfo: &titus.ContainerInfo{
			ImageName:   protobuf.String("titusoss/alpine"),
			Version:     protobuf.String("latest"),
			ImageDigest: protobuf.String("sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"),
		},
	}
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestNewContainer(t *testing.T) {
	taskID := "task-id"
	expectedAppName := "appName"
	expectedCPU := int64(2)
	expectedMem := int64(1024)
	expectedDisk := uint64(15000)
	expectedNetwork := uint32(256)
	expectedWorkloadType := BurstWorkloadType
	batch := true
	startTime := time.Now()
	expectedCmd := "/usr/bin/yes"
	expectedUserEnv := map[string]string{
		"MY_ENV": "is set",
	}
	expectedJobDetail := "detail"
	expectedJobStack := "stack"
	expectedJobSeq := "seq"
	expectedDigest := "abcd0123"
	expectedOwnerEmail := "user@email.org"
	expectedJobType := "SERVICE"

	expectedPassthroughAttributes := make(map[string]string)
	expectedPassthroughAttributes[ownerEmailPassThroughKey] = expectedOwnerEmail
	expectedPassthroughAttributes[jobTypePassThroughKey] = expectedJobType
	expectedCommand := "cmd arg0 arg1"

	containerInfo := &titus.ContainerInfo{
		AppName:   &expectedAppName,
		ImageName: protobuf.String("titusoss/alpine"),
		Version:   protobuf.String("latest"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			BandwidthLimitMbps: &expectedNetwork,
		},
		AllowCpuBursting:      &batch,
		Command:               &expectedCmd,
		UserProvidedEnv:       expectedUserEnv,
		JobGroupDetail:        &expectedJobDetail,
		JobGroupStack:         &expectedJobStack,
		JobGroupSequence:      &expectedJobSeq,
		ImageDigest:           &expectedDigest,
		PassthroughAttributes: expectedPassthroughAttributes,
		Process: &titus.ContainerInfo_Process{
			Command:    strings.Split(expectedCommand, " "),
			Entrypoint: strings.Split(expectedCommand, " "),
		},
	}

	resources := &Resources{
		CPU:     expectedCPU,
		Mem:     expectedMem,
		Disk:    expectedDisk,
		Network: uint64(expectedNetwork),
	}

	labels := make(map[string]string)
	config := config.Config{}

	container := NewContainer(taskID, containerInfo, resources, labels, config)

	actualAppName := container.Labels[appNameLabelKey]
	assert.Equal(t, expectedAppName, actualAppName)

	actualCommand := container.Labels[commandLabelKey]
	assert.Equal(t, expectedCommand, actualCommand)

	actualEntrypoint := container.Labels[entrypointLabelKey]
	assert.Equal(t, expectedCommand, actualEntrypoint)

	actualOwnerEmail := container.Labels[ownerEmailLabelKey]
	assert.Equal(t, expectedOwnerEmail, actualOwnerEmail)

	actualJobType := container.Labels[jobTypeLabelKey]
	assert.Equal(t, expectedJobType, actualJobType)

	actualCPU, _ := strconv.ParseInt(container.Labels[cpuLabelKey], 10, 64)
	assert.Equal(t, expectedCPU, actualCPU)

	actualMem, _ := strconv.ParseInt(container.Labels[memLabelKey], 10, 64)
	assert.Equal(t, expectedMem, actualMem)

	actualDisk, _ := strconv.ParseUint(container.Labels[diskLabelKey], 10, 64)
	assert.Equal(t, expectedDisk, actualDisk)

	actualNetwork, _ := strconv.ParseUint(container.Labels[networkLabelKey], 10, 32)
	assert.Equal(t, expectedNetwork, uint32(actualNetwork))

	actualWorkloadType := container.Labels[workloadTypeLabelKey]
	assert.Equal(t, expectedWorkloadType, WorkloadType(actualWorkloadType))

	// Default to false unless metatron is explicitly configured
	assert.Equal(t, container.Env["TITUS_METATRON_ENABLED"], "false")

	containerConfig, err := container.GetConfig(startTime)
	assert.NoError(t, err)

	assert.Equal(t, containerInfo, containerConfig)
	assert.NotNil(t, containerConfig.RunState)
	assert.Equal(t, *containerConfig.RunState.LaunchTimeUnixSec, uint64(startTime.Unix()))
	assert.Equal(t, *containerConfig.RunState.TaskId, taskID)
	assert.Equal(t, *containerConfig.RunState.HostName, taskID)
}

func TestMetatronEnabled(t *testing.T) {
	taskID := "task-id"
	expectedNetwork := uint32(256)
	batch := true

	containerInfo := &titus.ContainerInfo{
		ImageName: protobuf.String("titusoss/alpine"),
		Version:   protobuf.String("latest"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			BandwidthLimitMbps: &expectedNetwork,
		},
		AllowCpuBursting: &batch,
	}

	resources := &Resources{
		CPU:  int64(2),
		Mem:  int64(1024),
		Disk: uint64(15000),
	}

	labels := make(map[string]string)
	config := config.Config{
		MetatronEnabled: true,
	}

	container := NewContainer(taskID, containerInfo, resources, labels, config)
	assert.Equal(t, container.Env["TITUS_METATRON_ENABLED"], "true")
}
