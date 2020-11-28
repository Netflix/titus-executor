package types

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	protobuf "github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImageNameWithTag(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	expected := "docker.io/titusoss/alpine:latest"
	titusInfo.ImageName = protobuf.String("titusoss/alpine")
	titusInfo.Version = protobuf.String("latest")

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestImageTagLatestByDefault(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	expected := "docker.io/titusoss/alpine:latest"
	titusInfo.ImageName = protobuf.String("titusoss/alpine")

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestImageByDigest(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	expected := "docker.io/" +
		"titusoss/alpine@sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	titusInfo.ImageName = protobuf.String("titusoss/alpine")
	titusInfo.ImageDigest = protobuf.String("sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4")

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	if got := c.QualifiedImageName(); got != expected {
		t.Fatalf("Expected %s, got %s", expected, got)
	}
}

func TestImageByDigestIgnoresTag(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	expected := "docker.io/" +
		"titusoss/alpine@sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	titusInfo.ImageName = protobuf.String("titusoss/alpine")
	titusInfo.Version = protobuf.String("latest")
	titusInfo.ImageDigest = protobuf.String("sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4")

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
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
	cmd := "/usr/bin/yes"
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
	expectedEntrypoint := "entrypoint arg0 arg1"

	containerInfo := &titus.ContainerInfo{
		AppName:   &expectedAppName,
		ImageName: protobuf.String("titusoss/alpine"),
		Version:   protobuf.String("latest"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			BandwidthLimitMbps: &expectedNetwork,
		},
		AllowCpuBursting:      &batch,
		Command:               &cmd,
		UserProvidedEnv:       expectedUserEnv,
		JobGroupDetail:        &expectedJobDetail,
		JobGroupStack:         &expectedJobStack,
		JobGroupSequence:      &expectedJobSeq,
		ImageDigest:           &expectedDigest,
		PassthroughAttributes: expectedPassthroughAttributes,
		Process: &titus.ContainerInfo_Process{
			Command:    strings.Split(expectedCommand, " "),
			Entrypoint: strings.Split(expectedEntrypoint, " "),
		},
		IamProfile: protobuf.String("arn:aws:iam::0:role/DefaultContainerRole"),
	}

	resources := Resources{
		CPU:     expectedCPU,
		Mem:     expectedMem,
		Disk:    expectedDisk,
		Network: int64(expectedNetwork),
	}

	config := config.Config{}

	container, err := NewContainer(taskID, containerInfo, resources, config)
	require.Nil(t, err)

	actualAppNameLabel := container.Labels()[appNameLabelKey]
	assert.Equal(t, expectedAppName, actualAppNameLabel)

	actualCommandLabel := container.Labels()[commandLabelKey]
	assert.Equal(t, expectedCommand, actualCommandLabel)

	actualEntrypointLabel := container.Labels()[entrypointLabelKey]
	assert.Equal(t, expectedEntrypoint, actualEntrypointLabel)

	actualOwnerEmailLabel := container.Labels()[ownerEmailLabelKey]
	assert.Equal(t, expectedOwnerEmail, actualOwnerEmailLabel)

	actualJobTypeLabel := container.Labels()[jobTypeLabelKey]
	assert.Equal(t, expectedJobType, actualJobTypeLabel)

	actualCPULabel, _ := strconv.ParseInt(container.Labels()[cpuLabelKey], 10, 64)
	assert.Equal(t, expectedCPU, actualCPULabel)

	actualMemLabel, _ := strconv.ParseInt(container.Labels()[memLabelKey], 10, 64)
	assert.Equal(t, expectedMem, actualMemLabel)

	actualDiskLabel, _ := strconv.ParseInt(container.Labels()[diskLabelKey], 10, 64)
	assert.Equal(t, expectedDisk, actualDiskLabel)

	actualNetworkLabel, _ := strconv.ParseUint(container.Labels()[networkLabelKey], 10, 32)
	assert.Equal(t, expectedNetwork, uint32(actualNetworkLabel))

	actualWorkloadTypeLabel := container.Labels()[workloadTypeLabelKey]
	assert.Equal(t, expectedWorkloadType, WorkloadType(actualWorkloadTypeLabel))

	// Default to false unless metatron is explicitly configured
	assert.Equal(t, container.Env()["TITUS_METATRON_ENABLED"], "false")

	actualProcessEntrypoint, actualProcessCmd := container.Process()
	assert.Equal(t, actualProcessEntrypoint, []string{"entrypoint", "arg0", "arg1"})
	assert.Equal(t, actualProcessCmd, []string{"cmd", "arg0", "arg1"})

	containerConfig, err := ContainerConfig(container, startTime)
	assert.NoError(t, err)

	assert.Equal(t, containerInfo, containerConfig)
	assert.NotNil(t, containerConfig.RunState)
	assert.Equal(t, *containerConfig.RunState.LaunchTimeUnixSec, uint64(startTime.Unix()))
	assert.Equal(t, *containerConfig.RunState.TaskId, taskID)
	assert.Equal(t, *containerConfig.RunState.HostName, taskID)

	assert.False(t, container.ServiceMeshEnabled())
	scConfs, err := container.SidecarConfigs()
	require.Nil(t, err)
	svcMeshConf := scConfs[SidecarServiceServiceMesh]
	assert.NotNil(t, svcMeshConf)
	// service mesh image should be unset by default
	assert.Equal(t, svcMeshConf.Image, "")
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

	config := config.Config{
		MetatronEnabled: true,
	}

	container, err := NewContainer(taskID, containerInfo, resources, config)
	require.Nil(t, err)
	assert.Equal(t, container.Env()["TITUS_METATRON_ENABLED"], "true")
}

func TestClusterName(t *testing.T) {
	fixtures := []struct {
		appName        string
		jobGroupStack  string
		jobGroupDetail string
		expected       string
	}{
		{
			appName:        "app1",
			jobGroupStack:  "somestack",
			jobGroupDetail: "details",
			expected:       "app1-somestack-details",
		},
		{
			// no details
			appName:       "app2",
			jobGroupStack: "somestack",
			expected:      "app2-somestack",
		},
		{
			// no stack
			appName:        "app3",
			jobGroupDetail: "details",
			expected:       "app3--details",
		},
		{
			// no stack no details
			appName:  "app4",
			expected: "app4",
		},
	}

	for _, f := range fixtures {
		taskID, titusInfo, resources, conf, err := ContainerTestArgs()
		assert.NoError(t, err)
		if f.appName != "" {
			titusInfo.AppName = &f.appName
		}
		if f.jobGroupDetail != "" {
			titusInfo.JobGroupDetail = &f.jobGroupDetail
		}
		if f.jobGroupStack != "" {
			titusInfo.JobGroupStack = &f.jobGroupStack
		}

		c, err := NewContainer(taskID, titusInfo, *resources, *conf)
		assert.NoError(t, err)

		got := c.CombinedAppStackDetails()
		assert.Equal(t, f.expected, got)
	}
}

func TestEnvBasedOnTaskInfo(t *testing.T) {
	type input struct {
		info                             *titus.ContainerInfo
		cpu, mem, disk, networkBandwidth string
	}
	check := func(name string, input input, want map[string]string) func(*testing.T) {
		return func(t *testing.T) {
			var err error
			var resources Resources

			cfg, err := config.GenerateConfiguration(nil)
			require.Nil(t, err)
			cfg.SSHAccountID = "config"
			cfg.GetHardcodedEnv()

			if input.cpu == "" {
				input.cpu = "1"
				if _, ok := want["TITUS_NUM_CPU"]; !ok {
					want["TITUS_NUM_CPU"] = "1"
				}
			}
			if input.mem == "" {
				input.mem = "333"
				if _, ok := want["TITUS_NUM_MEM"]; !ok {
					want["TITUS_NUM_MEM"] = "333"
				}
			}
			if input.disk == "" {
				input.disk = "1000"
				if _, ok := want["TITUS_NUM_DISK"]; !ok {
					want["TITUS_NUM_DISK"] = "1000"
				}
			}
			if input.networkBandwidth == "" {
				input.networkBandwidth = "100"
				if _, ok := want["TITUS_NUM_NETWORK_BANDWIDTH"]; !ok {
					want["TITUS_NUM_NETWORK_BANDWIDTH"] = "100"
				}
			}

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
			container, err := NewContainer(name, input.info, resources, *cfg)
			require.Nil(t, err)
			containerEnv := container.Env()
			// Checks if everything in want is in containerEnv
			// basically, makes sure want is a subset of containerEnv
			// We merge the maps so we can use assert.equals
			for key, value := range containerEnv {
				if _, ok := want[key]; !ok {
					want[key] = value
				}
			}
			assert.Equal(t, want, containerEnv)
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
		{
			name: "CanOverrideResources",
			input: input{
				info: &titus.ContainerInfo{
					UserProvidedEnv: map[string]string{
						"TITUS_NUM_CPU": "42",
					},
				},
				cpu: "1",
			},
			want: map[string]string{
				"TITUS_NUM_CPU": "42",
			},
		},
		{
			name: "CannotOverrideIAM",
			input: input{
				info: &titus.ContainerInfo{
					UserProvidedEnv: map[string]string{
						"TITUS_IAM_ROLE": "arn:aws:iam::0:role/HackerRole",
					},
					IamProfile: protobuf.String("arn:aws:iam::0:role/RealRole"),
				},
			},
			want: map[string]string{
				"TITUS_IAM_ROLE": "arn:aws:iam::0:role/RealRole",
			},
		},
		{
			// the control plane should set the EC2_OWNER_ID variable
			name: "PreserveEC2OwnerID",
			input: input{
				info: &titus.ContainerInfo{
					UserProvidedEnv: map[string]string{
						"EC2_OWNER_ID": "good",
					},
					PassthroughAttributes: map[string]string{
						AccountIDParam: "default",
					},
				},
			},
			want: map[string]string{
				"EC2_OWNER_ID": "good",
			},
		},
		{
			name: "FallbackToAccountIDParam",
			input: input{
				info: &titus.ContainerInfo{
					UserProvidedEnv: map[string]string{},
					PassthroughAttributes: map[string]string{
						AccountIDParam: "default",
					},
				},
			},
			want: map[string]string{
				"EC2_OWNER_ID": "default",
			},
		},
		{
			name: "FallbackToConfig",
			input: input{
				info: &titus.ContainerInfo{
					UserProvidedEnv:       map[string]string{},
					PassthroughAttributes: map[string]string{},
				},
			},
			want: map[string]string{
				"EC2_OWNER_ID": "config",
			},
		},
	}

	for _, f := range fixtures {
		t.Run(f.name, check(f.name, f.input, f.want))
	}
}

func TestServiceMeshEnabled(t *testing.T) {
	imgName := "titusoss/test-svcmesh:latest"
	config := config.Config{
		ContainerServiceMeshEnabled: true,
	}

	taskID, titusInfo, resources, _, err := ContainerTestArgs()
	require.Nil(t, err)
	titusInfo.PassthroughAttributes = map[string]string{
		serviceMeshContainerParam: imgName,
		serviceMeshEnabledParam:   "true",
	}

	c, err := NewContainer(taskID, titusInfo, *resources, config)
	require.Nil(t, err)
	assert.True(t, c.ServiceMeshEnabled())
	scConfs, err := c.SidecarConfigs()
	require.Nil(t, err)
	svcMeshConf := scConfs[SidecarServiceServiceMesh]
	assert.NotNil(t, svcMeshConf)
	assert.Equal(t, svcMeshConf.Image, imgName)
}

func TestServiceMeshEnabledWithConfig(t *testing.T) {
	// If service mesh is set to enabled, but neither the `ProxydServiceImage` config value
	// or the passhtrough property are set, service mesh should end up disabled
	config := config.Config{
		ContainerServiceMeshEnabled: true,
	}

	taskID, titusInfo, resources, _, err := ContainerTestArgs()
	require.Nil(t, err)
	c, err := NewContainer(taskID, titusInfo, *resources, config)
	require.Nil(t, err)
	assert.False(t, c.ServiceMeshEnabled())
	scConfs, err := c.SidecarConfigs()
	require.Nil(t, err)
	svcMeshConf := scConfs[SidecarServiceServiceMesh]
	assert.NotNil(t, svcMeshConf)
	assert.Equal(t, svcMeshConf.Image, "")
}

func TestServiceMeshEnabledWithEmptyConfigValue(t *testing.T) {
	// Setting proxyd image to the empty string should result servicemesh being disabled
	config := config.Config{
		ContainerServiceMeshEnabled: true,
		ProxydServiceImage:          "",
	}

	taskID, titusInfo, resources, _, err := ContainerTestArgs()
	require.Nil(t, err)
	c, err := NewContainer(taskID, titusInfo, *resources, config)
	require.Nil(t, err)
	assert.False(t, c.ServiceMeshEnabled())
	scConfs, err := c.SidecarConfigs()
	require.Nil(t, err)
	svcMeshConf := scConfs[SidecarServiceServiceMesh]
	assert.NotNil(t, svcMeshConf)
	assert.Equal(t, svcMeshConf.Image, "")
}
