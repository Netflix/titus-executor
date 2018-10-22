package runtime

import (
	"strconv"
	"testing"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	protobuf "github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestImageNameWithTag(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	assert.NoError(t, err)
	expected := "docker.io/titusoss/alpine:latest"
	c := &runtimeTypes.Container{
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
	c := &runtimeTypes.Container{
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
	c := &runtimeTypes.Container{
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
	c := &runtimeTypes.Container{
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
	expectedCPU := int64(2)
	expectedMem := int64(1024)
	expectedDisk := uint64(15000)
	expectedNetwork := uint32(256)
	expectedWorkloadType := BurstWorkloadType
	batch := true

	containerInfo := &titus.ContainerInfo{
		ImageName: protobuf.String("titusoss/alpine"),
		Version:   protobuf.String("latest"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			BandwidthLimitMbps: &expectedNetwork,
		},
		AllowCpuBursting: &batch,
	}

	resources := &runtimeTypes.Resources{
		CPU:  expectedCPU,
		Mem:  expectedMem,
		Disk: expectedDisk,
	}

	labels := make(map[string]string)
	config := config.Config{}

	container := NewContainer(taskID, containerInfo, resources, labels, config)

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
}
