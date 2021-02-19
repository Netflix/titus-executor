package types

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types" // nolint: staticcheck
	podCommon "github.com/Netflix/titus-kube-common/pod"   // nolint: staticcheck
	"github.com/docker/go-units"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	ptr "k8s.io/utils/pointer"
)

var (
	stringNil           *string
	imageName           = "titusoss/alpine"
	imageFullWithLatest = "docker.io/titusoss/alpine:latest"
)

func addPodAnnotations(pod *corev1.Pod, annotations map[string]string) {
	for k, v := range annotations {
		pod.ObjectMeta.Annotations[k] = v
	}
}

func TestPodImageNameWithTag(t *testing.T) {
	_, _, _, pod, conf, err := ContainerTestArgs()
	assert.NilError(t, err)
	err = AddContainerInfoToPod(pod, &titus.ContainerInfo{})
	assert.NilError(t, err)

	uc := podCommon.GetUserContainer(pod)
	uc.Image = imageFullWithLatest
	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.QualifiedImageName(), imageFullWithLatest)
	assert.DeepEqual(t, c.ImageName(), ptr.StringPtr("titusoss/alpine"))
	assert.DeepEqual(t, c.ImageVersion(), ptr.StringPtr("latest"))
	assert.DeepEqual(t, c.ImageDigest(), stringNil)
}

func TestPodImageTagOmitLatest(t *testing.T) {
	_, _, _, pod, conf, err := ContainerTestArgs()
	assert.NilError(t, err)
	err = AddContainerInfoToPod(pod, &titus.ContainerInfo{})
	assert.NilError(t, err)

	// TODO: is this the behaviour we want?
	expected := "docker.io/titusoss/alpine"
	uc := podCommon.GetUserContainer(pod)
	uc.Image = expected

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.QualifiedImageName(), expected)
}

func TestPodImageByDigest(t *testing.T) {
	_, _, _, pod, conf, err := ContainerTestArgs()
	assert.NilError(t, err)
	err = AddContainerInfoToPod(pod, &titus.ContainerInfo{})
	assert.NilError(t, err)

	expDigest := "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	expected := "docker.io/" + imageName + "@" + expDigest

	uc := podCommon.GetUserContainer(pod)
	uc.Image = expected
	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.QualifiedImageName(), expected)
	assert.DeepEqual(t, c.ImageName(), ptr.StringPtr(imageName))
	assert.DeepEqual(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageDigest(), ptr.StringPtr(expDigest))
}

func TestNewPodContainer(t *testing.T) {
	taskID, _, _, pod, conf, err := ContainerTestArgs()
	assert.NilError(t, err)

	ipAddr := "1.2.3.4"
	expectedCommand := []string{"cmd", "arg0", "arg1"}
	expectedEntrypoint := []string{"entrypoint", "arg0", "arg1"}
	expIamRole := "arn:aws:iam::0:role/DefaultContainerRole"
	imgName := "titusoss/alpine"
	imgDigest := "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	expectedImage := "docker.io/" + imgName + "@" + imgDigest
	expAppName := "appName"
	expAppOwner := "user@example.com"
	expBwLimit := int64(128 * units.MB)
	expKillWaitSec := uint32(11)
	expNFSMounts := []NFSMount{
		{
			MountPoint: "/efs1",
			Server:     "fs-abcdef.efs.us-east-1.amazonaws.com",
			ServerPath: "/remote-dir",
			ReadOnly:   true,
		},
	}
	expOomScoreAdj := int32(99)
	expResources := &Resources{
		CPU:     2,
		GPU:     1,
		Mem:     512,
		Disk:    10000,
		Network: 128,
	}
	expSGs := []string{"sg-1", "sg-2"}
	expVPCalloc := &vpcTypes.HybridAllocation{
		IPV4Address: &vpcapi.UsableAddress{
			PrefixLength: 32,
			Address: &vpcapi.Address{
				Address: ipAddr,
			},
		},
		BranchENIID:     "eni-abcde",
		BranchENISubnet: "subnet-abcde",
		BranchENIVPC:    "vpc-abcde",
		ElasticAddress: &vpcapi.ElasticAddress{
			Ip: "1.2.3.5",
		},
	}

	addPodAnnotations(pod, map[string]string{
		podCommon.AnnotationKeyAppName:                  expAppName,
		podCommon.AnnotationKeyAppDetail:                "appDetail",
		podCommon.AnnotationKeyAppOwnerEmail:            expAppOwner,
		podCommon.AnnotationKeyAppStack:                 "appStack",
		podCommon.AnnotationKeyAppSequence:              "appSeq",
		podCommon.AnnotationKeyIAMRole:                  expIamRole,
		podCommon.AnnotationKeyJobID:                    "jobid",
		podCommon.AnnotationKeyJobType:                  "service",
		podCommon.AnnotationKeyLogKeepLocalFile:         True,
		podCommon.AnnotationKeyLogStdioCheckInterval:    "11m",
		podCommon.AnnotationKeyLogUploadCheckInterval:   "12m",
		podCommon.AnnotationKeyLogUploadThresholdTime:   "8h",
		podCommon.AnnotationKeyLogUploadRegexp:          ".*.foo",
		podCommon.AnnotationKeyNetworkAccountID:         "123456",
		podCommon.AnnotationKeyNetworkAssignIPv6Address: True,
		podCommon.AnnotationKeyNetworkBurstingEnabled:   True,
		// In a real job, both the pool and IP list wouldn't be set
		podCommon.AnnotationKeyNetworkElasticIPPool:       "pool1",
		podCommon.AnnotationKeyNetworkElasticIPs:          "eipalloc-001,eipalloc-002",
		podCommon.AnnotationKeyNetworkIMDSRequireToken:    "token",
		podCommon.AnnotationKeyPodCPUBurstingEnabled:      True,
		podCommon.AnnotationKeyPodFuseEnabled:             True,
		podCommon.AnnotationKeyPodKvmEnabled:              True,
		podCommon.AnnotationKeyPodOomScoreAdj:             "99",
		podCommon.AnnotationKeyPodSchedPolicy:             "idle",
		podCommon.AnnotationKeyPodSeccompAgentNetEnabled:  True,
		podCommon.AnnotationKeyPodSeccompAgentPerfEnabled: True,
		podCommon.AnnotationKeyNetworkSecurityGroups:      "sg-1,sg-2",
	})

	uc := podCommon.GetUserContainer(pod)
	uc.Args = expectedCommand
	uc.Command = expectedEntrypoint
	uc.Image = expectedImage
	pod.Spec.TerminationGracePeriodSeconds = ptr.Int64Ptr(11)

	//startTime := time.Now()
	cInfo := &titus.ContainerInfo{
		Process: &titus.ContainerInfo_Process{
			Command:    expectedCommand,
			Entrypoint: expectedEntrypoint,
		},
	}
	err = AddContainerInfoToPod(pod, cInfo)
	assert.NilError(t, err)

	// Add EFS mounts
	uc.VolumeMounts = []corev1.VolumeMount{
		{
			Name:      "efs-fs-abcdef-rwm.subdir1",
			MountPath: "/efs1",
		},
	}
	pod.Spec.Volumes = []corev1.Volume{
		{
			Name: "efs-fs-abcdef-rwm.subdir1",
			VolumeSource: corev1.VolumeSource{
				NFS: &corev1.NFSVolumeSource{
					Server:   "fs-abcdef.efs.us-east-1.amazonaws.com",
					Path:     "/remote-dir",
					ReadOnly: true,
				},
			},
		},
	}

	expCapabilities := &corev1.Capabilities{
		Add:  []corev1.Capability{"NET_ADMIN"},
		Drop: []corev1.Capability{"SYS_TIME"},
	}
	uc.SecurityContext = &corev1.SecurityContext{
		Capabilities: expCapabilities,
	}

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	c.SetVPCAllocation(expVPCalloc)
	c.SetID(taskID)

	assert.Equal(t, c.TaskID(), taskID)
	assert.DeepEqual(t, c.IPv4Address(), &ipAddr)
	assert.DeepEqual(t, c.HostnameStyle(), stringNil)

	entrypoint, cmd := c.Process()
	assert.DeepEqual(t, entrypoint, expectedEntrypoint)
	assert.DeepEqual(t, cmd, expectedCommand)

	var uint32Nil *uint32
	var gpuNil GPUContainer
	var metatronCredsNil *titus.ContainerInfo_MetatronCreds

	assert.Equal(t, c.AllowCPUBursting(), true)
	assert.Equal(t, c.AllowNetworkBursting(), true)
	assert.Equal(t, c.AppName(), "appName")
	assert.Equal(t, c.AssignIPv6Address(), true)
	assert.DeepEqual(t, c.BandwidthLimitMbps(), &expBwLimit)
	assert.DeepEqual(t, c.BatchPriority(), ptr.StringPtr("idle"))
	assert.DeepEqual(t, c.Capabilities(), expCapabilities)
	assert.Equal(t, c.CombinedAppStackDetails(), "appName-appStack-appDetail")
	assert.DeepEqual(t, c.NFSMounts(), expNFSMounts)

	expEnv := map[string]string{
		"AWS_METADATA_SERVICE_NUM_ATTEMPTS": "3",
		"AWS_METADATA_SERVICE_TIMEOUT":      "5",
		"EC2_DOMAIN":                        "amazonaws.com",
		"EC2_INTERFACE_ID":                  "eni-abcde",
		"EC2_LOCAL_IPV4":                    "1.2.3.4",
		"EC2_PUBLIC_IPV4":                   "1.2.3.5",
		"EC2_PUBLIC_IPV4S":                  "1.2.3.5",
		"EC2_OWNER_ID":                      "123456",
		"EC2_SUBNET_ID":                     "subnet-abcde",
		"EC2_VPC_ID":                        "vpc-abcde",
		"NETFLIX_APP":                       "appName",
		"NETFLIX_APPUSER":                   "appuser",
		"NETFLIX_AUTO_SCALE_GROUP":          "appName-appStack-appDetail-appSeq",
		"NETFLIX_CLUSTER":                   "appName-appStack-appDetail",
		"NETFLIX_DETAIL":                    "appDetail",
		"NETFLIX_STACK":                     "appStack",
		"TITUS_BATCH":                       "idle",
		"TITUS_CONTAINER_ID":                taskID,
		"TITUS_IAM_ROLE":                    expIamRole,
		"TITUS_IMAGE_DIGEST":                imgDigest,
		"TITUS_IMAGE_NAME":                  "titusoss/alpine",
		"TITUS_IMDS_REQUIRE_TOKEN":          "token",
		// XXX
		"TITUS_METATRON_ENABLED":      "true",
		"TITUS_NUM_CPU":               "2",
		"TITUS_NUM_DISK":              "10000",
		"TITUS_NUM_MEM":               "512",
		"TITUS_NUM_NETWORK_BANDWIDTH": "128",
		"TITUS_OCI_RUNTIME":           DefaultOciRuntime,
		"USER_SET_ENV1":               "var1",
		"USER_SET_ENV2":               "var2",
		"USER_SET_ENV3":               "var3",
	}

	expEnvArray := []string{}
	for k, v := range expEnv {
		expEnvArray = append(expEnvArray, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(expEnvArray)

	c.SetEnv("USER_SET_ENV1", "var1")
	c.SetEnvs(map[string]string{
		"USER_SET_ENV2": "var2",
		"USER_SET_ENV3": "var3",
	})
	assert.DeepEqual(t, c.Env(), expEnv)
	assert.DeepEqual(t, c.SortedEnvArray(), expEnvArray)

	assert.DeepEqual(t, c.ElasticIPPool(), ptr.StringPtr("pool1"))
	assert.DeepEqual(t, c.ElasticIPs(), ptr.StringPtr("eipalloc-001,eipalloc-002"))
	assert.Equal(t, c.FuseEnabled(), true)
	assert.Equal(t, c.GPUInfo(), gpuNil)
	assert.DeepEqual(t, c.IamRole(), ptr.StringPtr(expIamRole))
	assert.Equal(t, c.ID(), taskID)
	assert.DeepEqual(t, c.ImageDigest(), ptr.StringPtr(imgDigest))
	assert.DeepEqual(t, c.ImageName(), ptr.StringPtr("titusoss/alpine"))
	assert.Equal(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageTagForMetrics(), map[string]string{
		"image": imageName,
	})
	c.SetSystemD(true)
	assert.Equal(t, c.IsSystemD(), true)
	assert.Equal(t, c.JobGroupDetail(), "appDetail")
	assert.Equal(t, c.JobGroupStack(), "appStack")
	assert.Equal(t, c.JobGroupSequence(), "appSeq")
	assert.DeepEqual(t, c.JobID(), ptr.StringPtr("jobid"))
	assert.DeepEqual(t, c.JobType(), ptr.StringPtr("service"))
	assert.DeepEqual(t, c.KillWaitSeconds(), &expKillWaitSec)
	assert.Equal(t, c.KvmEnabled(), true)
	assert.DeepEqual(t, c.Labels(), map[string]string{
		appNameLabelKey:         expAppName,
		commandLabelKey:         strings.Join(expectedCommand, " "),
		entrypointLabelKey:      strings.Join(expectedEntrypoint, " "),
		ownerEmailLabelKey:      expAppOwner,
		jobTypeLabelKey:         "service",
		cpuLabelKey:             strconv.Itoa(int(expResources.CPU)),
		iamRoleLabelKey:         expIamRole,
		memLabelKey:             strconv.Itoa(int(expResources.Mem)),
		diskLabelKey:            strconv.Itoa(int(expResources.Disk)),
		networkLabelKey:         strconv.Itoa(int(expResources.Network)),
		titusTaskInstanceIDKey:  taskID,
		workloadTypeLabelKey:    string(BurstWorkloadType),
		models.ExecutorPidLabel: strconv.Itoa(os.Getpid()),
		models.TaskIDLabel:      taskID,
	})
	assert.Equal(t, c.LogKeepLocalFileAfterUpload(), true)

	expStdioCheckInterval, _ := time.ParseDuration("11m")
	expUploadCheckInterval, _ := time.ParseDuration("12m")
	expUploadThreshold, _ := time.ParseDuration("8h")
	assert.DeepEqual(t, c.LogStdioCheckInterval(), &expStdioCheckInterval)
	assert.DeepEqual(t, c.LogUploadCheckInterval(), &expUploadCheckInterval)
	assert.DeepEqual(t, c.LogUploaderConfig(), &uploader.Config{
		S3WriterRole: "",
		S3BucketName: "",
		S3PathPrefix: "",
	})

	logUploadRegExp := c.LogUploadRegexp()
	assert.Assert(t, logUploadRegExp != nil)
	assert.Equal(t, logUploadRegExp.String(), ".*.foo")
	assert.DeepEqual(t, c.LogUploadThresholdTime(), &expUploadThreshold)

	assert.Equal(t, c.MetatronCreds(), metatronCredsNil)
	zero := int(0)
	assert.DeepEqual(t, c.NormalizedENIIndex(), &zero)
	assert.DeepEqual(t, c.OomScoreAdj(), &expOomScoreAdj)
	assert.Equal(t, c.QualifiedImageName(), expectedImage)

	assert.DeepEqual(t, c.Resources(), expResources)
	assert.DeepEqual(t, c.RequireIMDSToken(), ptr.StringPtr("token"))
	assert.Equal(t, c.Runtime(), "runc")
	assert.Equal(t, c.SeccompAgentEnabledForNetSyscalls(), true)
	assert.Equal(t, c.SeccompAgentEnabledForPerfSyscalls(), true)
	assert.DeepEqual(t, c.SecurityGroupIDs(), &expSGs)
	assert.Equal(t, c.ServiceMeshEnabled(), false)
	assert.Equal(t, c.ShmSizeMiB(), uint32Nil)

	sidecars, err := c.SidecarConfigs()
	assert.NilError(t, err)
	// XXX:
	assert.DeepEqual(t, sidecars,
		map[string]*SidecarContainerConfig{
			SidecarServiceAbMetrix:    {ServiceName: "abmetrix", Volumes: map[string]struct{}{"/titus/abmetrix": {}}},
			SidecarServiceLogViewer:   {ServiceName: "logviewer", Volumes: map[string]struct{}{"/titus/adminlogs": {}}},
			SidecarServiceMetatron:    {ServiceName: "metatron", Volumes: map[string]struct{}{"/titus/metatron": {}}},
			SidecarServiceServiceMesh: {ServiceName: "servicemesh", Volumes: map[string]struct{}{"/titus/proxyd": {}}},
			SidecarServiceSpectatord:  {ServiceName: "spectatord", Volumes: map[string]struct{}{"/titus/spectatord": {}}},
			SidecarServiceSshd:        {ServiceName: "sshd", Volumes: map[string]struct{}{"/titus/sshd": {}}},
		})

	assert.Equal(t, c.SignedAddressAllocationUUID(), stringNil)
	assert.Equal(t, c.SubnetIDs(), stringNil)
	assert.Equal(t, c.TTYEnabled(), false)
	assert.Equal(t, c.UploadDir("foo"), "titan/mainvpc/foo/"+taskID)
	assert.Equal(t, c.UseJumboFrames(), false)
	assert.DeepEqual(t, c.VPCAllocation(), expVPCalloc)
	assert.DeepEqual(t, c.VPCAccountID(), ptr.StringPtr("123456"))
}

// XXX
/*
func TestNewPodContainerErrors(t *testing.T) {
	ipAddr := ""
	_, err := NewPodContainer(nil, &ipAddr)
	assert.Error(t, err, "missing pod")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: taskID,
		},
	}
	_, err = NewPodContainer(pod, nil)
	assert.Error(t, err, "missing ipv4 address")

	// XXX: missing schema version annotation

	_, err = NewPodContainer(pod, &ipAddr)
	assert.Error(t, err, "unable to find containerInfo annotation")

	pod.Annotations = map[string]string{
		"containerInfo": "0",
	}
	_, err = NewPodContainer(pod, &ipAddr)
	assert.Error(t, err, "unable to base64 decode containerInfo annotation: illegal base64 data at input byte 0")

	pod.Annotations["containerInfo"] = base64.StdEncoding.EncodeToString([]byte("blah"))
	_, err = NewPodContainer(pod, &ipAddr)
	assert.Error(t, err, "unable to decode containerInfo protobuf: unexpected EOF")

	cInfo := &titus.ContainerInfo{
		PassthroughAttributes: map[string]string{
			hostnameStyleParam: "invalid",
		},
	}
	addContainerInfoToPod(t, pod, cInfo)
	_, err = NewPodContainer(pod, &ipAddr)
	assert.Error(t, err, "unknown hostname style: invalid")
}

func TestNewPodContainerHostnameStyle(t *testing.T) {
	ipAddr := "1.2.3.4"

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: taskID,
		},
	}
	cInfo := &titus.ContainerInfo{
		PassthroughAttributes: map[string]string{
			hostnameStyleParam: "ec2",
		},
	}

	addContainerInfoToPod(t, pod, cInfo)
	c, err := NewPodContainer(pod, &ipAddr)
	assert.NilError(t, err)
	assert.DeepEqual(t, c.HostnameStyle(), ptr.StringPtr("ec2"))
}
*/

// TODO:
// - log uploading durations
