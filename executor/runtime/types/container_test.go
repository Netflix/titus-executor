package types

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/models"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	protobuf "github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImageNameWithTag(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	assert.NoError(t, err)
	expected := "docker.io/titusoss/alpine:latest"
	c := &Container{
		Config: *cfg,
		TitusInfo: &titus.ContainerInfo{
			ImageName:  protobuf.String("titusoss/alpine"),
			Version:    protobuf.String("latest"),
			IamProfile: protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
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
	expectedDisk := int64(15000)
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
		IamProfile: protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
	}

	resources := Resources{
		CPU:     expectedCPU,
		Mem:     expectedMem,
		Disk:    expectedDisk,
		Network: int64(expectedNetwork),
	}

	labels := make(map[string]string)
	config := config.Config{}

	container, err := NewContainer(taskID, containerInfo, resources, labels, config)
	require.Nil(t, err)

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

	actualDisk, _ := strconv.ParseInt(container.Labels[diskLabelKey], 10, 64)
	assert.Equal(t, expectedDisk, actualDisk)

	actualNetwork, _ := strconv.ParseUint(container.Labels[networkLabelKey], 10, 32)
	assert.Equal(t, expectedNetwork, uint32(actualNetwork))

	actualWorkloadType := container.Labels[workloadTypeLabelKey]
	assert.Equal(t, expectedWorkloadType, WorkloadType(actualWorkloadType))

	// Default to false unless metatron is explicitly configured
	assert.Equal(t, container.GetEnv()["TITUS_METATRON_ENABLED"], "false")

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
		IamProfile:       protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
	}

	resources := Resources{
		CPU:  2,
		Mem:  1024,
		Disk: 15000,
	}

	labels := make(map[string]string)
	config := config.Config{
		MetatronEnabled: true,
	}

	container, err := NewContainer(taskID, containerInfo, resources, labels, config)
	require.Nil(t, err)
	assert.Equal(t, container.GetEnv()["TITUS_METATRON_ENABLED"], "true")
}

func TestClusterName(t *testing.T) {
	fixtures := []struct {
		input *titus.ContainerInfo
		want  string
	}{
		{
			input: &titus.ContainerInfo{
				AppName:        protobuf.String("app1"),
				JobGroupStack:  protobuf.String("somestack"),
				JobGroupDetail: protobuf.String("details"),
			},
			want: "app1-somestack-details",
		},
		{
			// no details
			input: &titus.ContainerInfo{
				AppName:       protobuf.String("app2"),
				JobGroupStack: protobuf.String("somestack"),
			},
			want: "app2-somestack",
		},
		{
			// no stack
			input: &titus.ContainerInfo{
				AppName:        protobuf.String("app3"),
				JobGroupDetail: protobuf.String("details"),
			},
			want: "app3--details",
		},
		{
			// no stack no details
			input: &titus.ContainerInfo{
				AppName: protobuf.String("app4"),
			},
			want: "app4",
		},
	}

	for _, f := range fixtures {
		if got := combineAppStackDetails(f.input); got != f.want {
			t.Fatalf("want: %s, got %s", f.want, got)
		}
	}
}

func TestEnvBasedOnTaskInfo(t *testing.T) {
	cfg, err := config.GenerateConfiguration(nil)
	require.Nil(t, err)
	cfg.GetHardcodedEnv()

	type input struct {
		info                             *titus.ContainerInfo
		cpu, mem, disk, networkBandwidth string
	}
	check := func(name string, input input, want map[string]string) func(*testing.T) {
		return func(t *testing.T) {
			var err error
			var resources Resources

			resources.Mem, err = strconv.ParseInt(input.mem, 10, 64)
			require.Nil(t, err)

			resources.CPU, err = strconv.ParseInt(input.cpu, 10, 64)
			require.Nil(t, err)

			resources.Disk, err = strconv.ParseInt(input.disk, 10, 64)
			require.Nil(t, err)

			resources.Network, err = strconv.ParseInt(input.networkBandwidth, 10, 64)
			require.Nil(t, err)

			if input.info.IamProfile == nil {
				input.info.IamProfile = protobuf.String("arn:aws:iam::0:role/DefaultContainerRole")
			}
			container, err := NewContainer(name, input.info, resources, map[string]string{models.TaskIDLabel: name}, *cfg)
			require.Nil(t, err)
			containerEnv := container.GetEnv()
			for key, value := range want {
				assert.Contains(t, containerEnv, key)
				assert.Equalf(t, containerEnv[key], value, "Expected key %s to be equal", key)
			}
		}
	}

	fixtures := []struct {
		name  string
		input input
		want  map[string]string
	}{
		{
			name: "Full",
			input: input{
				info: &titus.ContainerInfo{
					AppName:          protobuf.String("app1"),
					ImageName:        protobuf.String("image1"),
					Version:          protobuf.String("stable"),
					ImageDigest:      protobuf.String("digest1"),
					JobGroupStack:    protobuf.String("stack1"),
					JobGroupDetail:   protobuf.String("detail1"),
					JobGroupSequence: protobuf.String("v001"),
				},
				cpu:              "1",
				mem:              "100",
				disk:             "1000",
				networkBandwidth: "100",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_CLUSTER":             "app1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-stack1-detail1-v001",
				"TITUS_NUM_CPU":               "1",
				"TITUS_NUM_MEM":               "100",
				"TITUS_NUM_DISK":              "1000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "100",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "stable",
				"TITUS_IMAGE_DIGEST":          "digest1",
			},
		},
		{
			name: "NoName",
			input: input{
				info: &titus.ContainerInfo{
					AppName:          protobuf.String("image1"),
					ImageName:        protobuf.String("image1"),
					JobGroupStack:    protobuf.String("stack1"),
					JobGroupDetail:   protobuf.String("detail1"),
					JobGroupSequence: protobuf.String("v001"),
				},
				cpu:              "2",
				mem:              "200",
				disk:             "2000",
				networkBandwidth: "200",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "image1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_CLUSTER":             "image1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "image1-stack1-detail1-v001",
				"TITUS_NUM_CPU":               "2",
				"TITUS_NUM_MEM":               "200",
				"TITUS_NUM_DISK":              "2000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "200",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoStack",
			input: input{
				info: &titus.ContainerInfo{
					AppName:          protobuf.String("app1"),
					ImageName:        protobuf.String("image1"),
					JobGroupDetail:   protobuf.String("detail1"),
					JobGroupSequence: protobuf.String("v001"),
				},
				cpu:              "3",
				mem:              "300",
				disk:             "3000",
				networkBandwidth: "300",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_STACK":               "",
				"NETFLIX_CLUSTER":             "app1--detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1--detail1-v001",
				"TITUS_NUM_CPU":               "3",
				"TITUS_NUM_MEM":               "300",
				"TITUS_NUM_DISK":              "3000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "300",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoDetail",
			input: input{
				info: &titus.ContainerInfo{
					AppName:          protobuf.String("app1"),
					ImageName:        protobuf.String("image1"),
					JobGroupStack:    protobuf.String("stack1"),
					JobGroupSequence: protobuf.String("v001"),
				},
				cpu:              "4",
				mem:              "400",
				disk:             "4000",
				networkBandwidth: "400",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "app1-stack1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-stack1-v001",
				"TITUS_NUM_CPU":               "4",
				"TITUS_NUM_MEM":               "400",
				"TITUS_NUM_DISK":              "4000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "400",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoSequence",
			input: input{
				info: &titus.ContainerInfo{
					AppName:        protobuf.String("app1"),
					ImageName:      protobuf.String("image1"),
					JobGroupStack:  protobuf.String("stack1"),
					JobGroupDetail: protobuf.String("detail1"),
				},
				cpu:              "5",
				mem:              "500",
				disk:             "5000",
				networkBandwidth: "500",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "stack1",
				"NETFLIX_DETAIL":              "detail1",
				"NETFLIX_CLUSTER":             "app1-stack1-detail1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-stack1-detail1-v000",
				"TITUS_NUM_CPU":               "5",
				"TITUS_NUM_MEM":               "500",
				"TITUS_NUM_DISK":              "5000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "500",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoStackNoDetail",
			input: input{
				info: &titus.ContainerInfo{
					AppName:          protobuf.String("app1"),
					ImageName:        protobuf.String("image1"),
					JobGroupSequence: protobuf.String("v001"),
				},
				cpu:              "6",
				mem:              "600",
				disk:             "6000",
				networkBandwidth: "600",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "app1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-v001",
				"TITUS_NUM_CPU":               "6",
				"TITUS_NUM_MEM":               "600",
				"TITUS_NUM_DISK":              "6000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "600",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoStackNoDetailNoSequence",
			input: input{
				info: &titus.ContainerInfo{
					AppName:   protobuf.String("app1"),
					ImageName: protobuf.String("image1"),
				},
				cpu:              "7",
				mem:              "700",
				disk:             "7000",
				networkBandwidth: "700",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "app1",
				"NETFLIX_STACK":               "",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "app1",
				"NETFLIX_AUTO_SCALE_GROUP":    "app1-v000",
				"TITUS_NUM_CPU":               "7",
				"TITUS_NUM_MEM":               "700",
				"TITUS_NUM_DISK":              "7000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "700",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoNameNoStackNoDetailNoSequence",
			input: input{
				info: &titus.ContainerInfo{
					ImageName: protobuf.String("image1"),
					AppName:   protobuf.String("image1"),
				},
				cpu:              "8",
				mem:              "800",
				disk:             "8000",
				networkBandwidth: "800",
			},
			want: map[string]string{
				"NETFLIX_APP":                 "image1",
				"NETFLIX_STACK":               "",
				"NETFLIX_DETAIL":              "",
				"NETFLIX_CLUSTER":             "image1",
				"NETFLIX_AUTO_SCALE_GROUP":    "image1-v000",
				"TITUS_NUM_CPU":               "8",
				"TITUS_NUM_MEM":               "800",
				"TITUS_NUM_DISK":              "8000",
				"TITUS_NUM_NETWORK_BANDWIDTH": "800",
				"TITUS_IMAGE_NAME":            "image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, check(f.name, f.input, f.want))
	}
}
