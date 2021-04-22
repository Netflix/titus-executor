package types

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types" // nolint: staticcheck
	podCommon "github.com/Netflix/titus-kube-common/pod"   // nolint: staticcheck
	"github.com/docker/go-units"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ptr "k8s.io/utils/pointer"
)

var (
	stringNil           *string
	imageName           = "titusoss/alpine"
	imageFullWithLatest = "docker.io/titusoss/alpine:latest"
	testDigest          = "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
)

func addPodAnnotations(pod *corev1.Pod, annotations map[string]string) {
	for k, v := range annotations {
		pod.ObjectMeta.Annotations[k] = v
	}
}

func TestPodImageNameWithTag(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
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
	pod, conf, err := PodContainerTestArgs()
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
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	expected := "docker.io/" + imageName + "@" + testDigest

	uc := podCommon.GetUserContainer(pod)
	uc.Image = expected
	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.QualifiedImageName(), expected)
	assert.DeepEqual(t, c.ImageName(), ptr.StringPtr(imageName))
	assert.DeepEqual(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageDigest(), ptr.StringPtr(testDigest))
}

func TestNewPodContainer(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)
	taskID := pod.ObjectMeta.Name

	ipAddr := "1.2.3.4"
	expectedCommand := []string{"cmd", "arg0", "arg1"}
	expectedEntrypoint := []string{"entrypoint", "arg0", "arg1"}
	imgName := "titusoss/alpine"
	imgDigest := "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	expectedImage := "docker.io/" + imgName + "@" + imgDigest
	expAppName := "appName"
	expAppOwner := "user@example.com"
	expBwLimit := int64(128 * units.MB)
	expCapabilities := &corev1.Capabilities{
		Add:  []corev1.Capability{"NET_ADMIN"},
		Drop: []corev1.Capability{"SYS_TIME"},
	}
	expKillWaitSec := uint32(11)
	expNFSMounts := []NFSMount{
		{
			MountPoint: "/efs1",
			Server:     "fs-abcdef.efs.us-east-1.amazonaws.com",
			ServerPath: "/remote-dir",
			ReadOnly:   true,
		},
	}
	expEBSMount := EBSInfo{
		VolumeID:  "vol-abcdef",
		MountPath: "/ebs_mnt",
		MountPerm: "RO",
		FSType:    "xfs",
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
	expShmSize := uint32(256)
	expSubnets := []string{"subnet-1", "subnet-2"}
	expSvcMeshImage := "docker.io/titusoss/servicemesh:latest"
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
		podCommon.AnnotationKeyIAMRole:                  testIamRole,
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
		podCommon.AnnotationKeyNetworkElasticIPPool:          "pool1",
		podCommon.AnnotationKeyNetworkElasticIPs:             "eipalloc-001,eipalloc-002",
		podCommon.AnnotationKeyNetworkIMDSRequireToken:       "token",
		podCommon.AnnotationKeyPodCPUBurstingEnabled:         True,
		podCommon.AnnotationKeyPodFuseEnabled:                True,
		podCommon.AnnotationKeyPodKvmEnabled:                 True,
		podCommon.AnnotationKeyPodOomScoreAdj:                "99",
		podCommon.AnnotationKeyPodSchedPolicy:                "idle",
		podCommon.AnnotationKeyPodSeccompAgentNetEnabled:     True,
		podCommon.AnnotationKeyPodSeccompAgentPerfEnabled:    True,
		podCommon.AnnotationKeyNetworkSecurityGroups:         "sg-1,sg-2",
		podCommon.AnnotationKeyNetworkSubnetIDs:              strings.Join(expSubnets, ","),
		podCommon.AnnotationKeyNetworkJumboFramesEnabled:     True,
		podCommon.AnnotationKeyNetworkStaticIPAllocationUUID: "static-ip-uuid",
		// Add servicemesh sidecar
		podCommon.AnnotationKeyServicePrefix + "/servicemesh.v1.enabled": True,
		podCommon.AnnotationKeyServicePrefix + "/servicemesh.v1.image":   "titusoss/servicemesh:latest",
	})

	uc := podCommon.GetUserContainer(pod)
	uc.Args = expectedCommand
	uc.Command = expectedEntrypoint
	uc.Image = expectedImage
	pod.Spec.TerminationGracePeriodSeconds = ptr.Int64Ptr(11)

	cInfo := &titus.ContainerInfo{
		Process: &titus.ContainerInfo_Process{
			Command:    expectedCommand,
			Entrypoint: expectedEntrypoint,
		},
	}
	err = AddContainerInfoToPod(pod, cInfo)
	assert.NilError(t, err)

	// Add EFS, NFS, SHM mounts
	uc.VolumeMounts = []corev1.VolumeMount{
		{
			Name:      "efs-fs-abcdef-rwm.subdir1",
			MountPath: "/efs1",
		},
		{
			Name:      "dev-shm",
			MountPath: "/dev/shm",
		},
		{
			Name:      "ebs-vol-abcdef",
			MountPath: "/ebs_mnt",
		},
	}
	shmRes := resource.MustParse("256Mi")
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
		{
			Name: "dev-shm",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium:    corev1.StorageMediumMemory,
					SizeLimit: &shmRes,
				},
			},
		},
		{
			Name: "ebs-vol-abcdef",
			VolumeSource: corev1.VolumeSource{
				AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{
					VolumeID: "vol-abcdef",
					FSType:   "xfs",
					ReadOnly: true,
				},
			},
		},
	}

	uc.SecurityContext = &corev1.SecurityContext{
		Capabilities: expCapabilities,
	}
	uc.TTY = true

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
	assert.DeepEqual(t, c.EBSInfo(), expEBSMount)

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
		"TITUS_IAM_ROLE":                    testIamRole,
		"TITUS_IMAGE_DIGEST":                imgDigest,
		"TITUS_IMAGE_NAME":                  "titusoss/alpine",
		"TITUS_IMDS_REQUIRE_TOKEN":          "token",
		"TITUS_METATRON_ENABLED":            True,
		"TITUS_NUM_CPU":                     "2",
		"TITUS_NUM_DISK":                    "10000",
		"TITUS_NUM_MEM":                     "512",
		"TITUS_NUM_NETWORK_BANDWIDTH":       "128",
		"TITUS_OCI_RUNTIME":                 DefaultOciRuntime,
		"USER_SET_ENV1":                     "var1",
		"USER_SET_ENV2":                     "var2",
		"USER_SET_ENV3":                     "var3",
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
	assert.DeepEqual(t, c.IamRole(), ptr.StringPtr(testIamRole))
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
		iamRoleLabelKey:         testIamRole,
		memLabelKey:             strconv.Itoa(int(expResources.Mem)),
		diskLabelKey:            strconv.Itoa(int(expResources.Disk)),
		networkLabelKey:         strconv.Itoa(int(expResources.Network)),
		TitusTaskInstanceIDKey:  taskID,
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
	assert.Equal(t, c.ServiceMeshEnabled(), true)
	assert.DeepEqual(t, c.ShmSizeMiB(), &expShmSize)

	sidecars, err := c.SidecarConfigs()
	assert.NilError(t, err)
	//sort.Slice(sidecars, func(i, j int) bool { return sidecars[i].ServiceName < sidecars[j].ServiceName })
	sidecarNames := []string{}
	svcMeshImage := ""
	for _, sc := range sidecars {
		sidecarNames = append(sidecarNames, sc.ServiceName)
		if sc.ServiceName == SidecarServiceServiceMesh {
			svcMeshImage = sc.Image
		}
	}
	assert.DeepEqual(t, sidecarNames,
		[]string{
			SidecarTitusContainer,
			SidecarServiceSpectatord,
			SidecarServiceAtlasd,
			SidecarServiceAtlasAgent,
			SidecarServiceSshd,
			SidecarServiceMetadataProxy,
			SidecarServiceMetatron,
			SidecarServiceLogViewer,
			SidecarServiceServiceMesh,
			SidecarServiceAbMetrix,
			SidecarSeccompAgent,
			SidecarTitusStorage,
		})
	assert.Equal(t, svcMeshImage, expSvcMeshImage)

	assert.DeepEqual(t, c.SignedAddressAllocationUUID(), ptr.StringPtr("static-ip-uuid"))
	assert.DeepEqual(t, c.SubnetIDs(), &expSubnets)
	assert.Equal(t, c.TTYEnabled(), true)
	assert.Equal(t, c.UploadDir("foo"), "titan/mainvpc/foo/"+taskID)
	assert.Equal(t, c.UseJumboFrames(), true)
	assert.DeepEqual(t, c.VPCAllocation(), expVPCalloc)
	assert.DeepEqual(t, c.VPCAccountID(), ptr.StringPtr("123456"))
}

func TestNewPodContainerErrors(t *testing.T) {
	goodPod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)
	taskID := goodPod.ObjectMeta.Name

	_, err = NewPodContainer(nil, *conf)
	assert.Error(t, err, "missing pod")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: taskID,
		},
	}
	_, err = NewPodContainer(pod, *conf)
	assert.Error(t, err, "no containers found in pod")

	pod = &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: taskID,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: taskID,
				},
			},
		},
	}

	_, err = NewPodContainer(pod, *conf)
	assert.ErrorContains(t, err, "pod did not contain network resource limit")

	pod.Spec.Containers[0].Resources = goodPod.Spec.Containers[0].Resources
	_, err = NewPodContainer(pod, *conf)
	assert.ErrorContains(t, err, "unable to find containerInfo annotation")

	pod.Annotations = map[string]string{
		podCommon.AnnotationKeyPodTitusContainerInfo: "0",
	}
	_, err = NewPodContainer(pod, *conf)
	assert.ErrorContains(t, err, "unable to base64 decode containerInfo annotation: illegal base64 data")

	pod.Annotations[podCommon.AnnotationKeyPodTitusContainerInfo] = base64.StdEncoding.EncodeToString([]byte("blah"))
	_, err = NewPodContainer(pod, *conf)
	assert.Error(t, err, "unable to decode containerInfo protobuf: unexpected EOF")

	err = AddContainerInfoToPod(pod, &titus.ContainerInfo{})
	assert.NilError(t, err)

	_, err = NewPodContainer(pod, *conf)
	assert.ErrorContains(t, err, "error parsing docker image \"\"")

	pod.Spec.Containers[0].Image = testImageWithTag
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
		Name:      "dev-shm",
		MountPath: ShmMountPath,
	})
	_, err = NewPodContainer(pod, *conf)
	assert.Error(t, err, "error parsing EmptyDir mounts: container volume mount found with unmatched pod volume: dev-shm")

	// Can't specify more than one EBS volume per task
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
		{
			Name:      "ebs-vol-1",
			MountPath: "/ebs_mnt1",
		},
		{
			Name:      "ebs-vol-2",
			MountPath: "/ebs_mnt2",
		},
	}
	pod.Spec.Volumes = []corev1.Volume{
		{
			Name: "ebs-vol-1",
			VolumeSource: corev1.VolumeSource{
				AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{
					VolumeID: "vol-1",
					FSType:   "xfs",
					ReadOnly: true,
				},
			},
		},
		{
			Name: "ebs-vol-2",
			VolumeSource: corev1.VolumeSource{
				AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{
					VolumeID: "vol-2",
					FSType:   "xfs",
					ReadOnly: true,
				},
			},
		},
	}
	_, err = NewPodContainer(pod, *conf)
	assert.Error(t, err, "error parsing mounts: only one EBS volume per task can be specified")
}

func TestNewPodContainerHostnameStyle(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	addPodAnnotations(pod, map[string]string{
		podCommon.AnnotationKeyPodHostnameStyle: "ec2",
	})

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.DeepEqual(t, c.HostnameStyle(), ptr.StringPtr("ec2"))
}

func TestNewPodContainerMetatronDisabled(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	conf.MetatronEnabled = false

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.Env()["TITUS_METATRON_ENABLED"], "false")
}

func TestPodContainerClusterName(t *testing.T) {
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
		pod, conf, err := PodContainerTestArgs()
		assert.NilError(t, err)

		if f.appName != "" {
			pod.Annotations[podCommon.AnnotationKeyAppName] = f.appName
		}
		if f.jobGroupDetail != "" {
			pod.Annotations[podCommon.AnnotationKeyAppDetail] = f.jobGroupDetail
		}
		if f.jobGroupStack != "" {
			pod.Annotations[podCommon.AnnotationKeyAppStack] = f.jobGroupStack
		}

		c, err := NewPodContainer(pod, *conf)
		assert.NilError(t, err)

		got := c.CombinedAppStackDetails()
		assert.Equal(t, f.expected, got)
	}
}

func TestPodContainerEnvBasedOnTaskInfo(t *testing.T) {
	type input struct {
		annotations, env                        map[string]string
		cpu, mem, disk, image, networkBandwidth string
	}
	check := func(name string, input input, want map[string]string) func(*testing.T) {
		return func(t *testing.T) {
			var err error
			var resources Resources

			pod, conf, err := PodContainerTestArgs()
			assert.NilError(t, err)

			conf.SSHAccountID = "config"
			conf.GetHardcodedEnv()

			if input.cpu == "" {
				input.cpu = "1"
				if _, ok := want["TITUS_NUM_CPU"]; !ok {
					want["TITUS_NUM_CPU"] = input.cpu
				}
			}
			if input.mem == "" {
				input.mem = "333"
				if _, ok := want["TITUS_NUM_MEM"]; !ok {
					want["TITUS_NUM_MEM"] = input.mem
				}
			}
			if input.disk == "" {
				input.disk = "1000"
				if _, ok := want["TITUS_NUM_DISK"]; !ok {
					want["TITUS_NUM_DISK"] = input.disk
				}
			}
			if input.networkBandwidth == "" {
				input.networkBandwidth = "100"
				if _, ok := want["TITUS_NUM_NETWORK_BANDWIDTH"]; !ok {
					want["TITUS_NUM_NETWORK_BANDWIDTH"] = input.networkBandwidth
				}
			}

			if input.image != "" {
				pod.Spec.Containers[0].Image = input.image
			}

			resources.Mem, err = strconv.ParseInt(input.mem, 10, 64)
			assert.NilError(t, err)

			resources.CPU, err = strconv.ParseInt(input.cpu, 10, 64)
			assert.NilError(t, err)

			resources.Disk, err = strconv.ParseInt(input.disk, 10, 64)
			assert.NilError(t, err)

			resources.Network, err = strconv.ParseInt(input.networkBandwidth, 10, 64)
			assert.NilError(t, err)

			resourceReqs := ResourcesToPodResourceRequirements(&resources)
			pod.Spec.Containers[0].Resources = resourceReqs

			for k, v := range input.annotations {
				pod.Annotations[k] = v
			}
			for k, v := range input.env {
				pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
					Name:  k,
					Value: v,
				})
			}

			if _, ok := pod.Annotations[podCommon.AnnotationKeyIAMRole]; !ok {
				pod.Annotations[podCommon.AnnotationKeyIAMRole] = testIamRole
			}
			container, err := NewPodContainer(pod, *conf)
			assert.NilError(t, err)
			containerEnv := container.Env()
			// Checks if everything in want is in containerEnv
			// basically, makes sure want is a subset of containerEnv
			// We merge the maps so we can use assert.equals
			for key, value := range containerEnv {
				if _, ok := want[key]; !ok {
					want[key] = value
				}
			}
			assert.DeepEqual(t, want, containerEnv)
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
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName:     "app1",
					podCommon.AnnotationKeyAppStack:    "stack1",
					podCommon.AnnotationKeyAppDetail:   "detail1",
					podCommon.AnnotationKeyAppSequence: "v001",
				},
				image:            "titusops/image1@" + testDigest,
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_DIGEST":          testDigest,
			},
		},
		{
			name: "NoName",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName:     "image1",
					podCommon.AnnotationKeyAppStack:    "stack1",
					podCommon.AnnotationKeyAppDetail:   "detail1",
					podCommon.AnnotationKeyAppSequence: "v001",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoStack",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName:     "app1",
					podCommon.AnnotationKeyAppDetail:   "detail1",
					podCommon.AnnotationKeyAppSequence: "v001",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoDetail",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName:     "app1",
					podCommon.AnnotationKeyAppStack:    "stack1",
					podCommon.AnnotationKeyAppSequence: "v001",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoSequence",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName:   "app1",
					podCommon.AnnotationKeyAppStack:  "stack1",
					podCommon.AnnotationKeyAppDetail: "detail1",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoStackNoDetail",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName:     "app1",
					podCommon.AnnotationKeyAppSequence: "v001",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoStackNoDetailNoSequence",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName: "app1",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "NoNameNoStackNoDetailNoSequence",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyAppName: "image1",
				},
				image:            "titusops/image1:latest",
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
				"TITUS_IMAGE_NAME":            "titusops/image1",
				"TITUS_IMAGE_TAG":             "latest",
			},
		},
		{
			name: "CanOverrideResources",
			input: input{
				env: map[string]string{
					"TITUS_NUM_CPU": "42",
				},
				annotations: map[string]string{},
				cpu:         "1",
			},
			want: map[string]string{
				"TITUS_NUM_CPU": "42",
			},
		},
		{
			name: "CannotOverrideIAM",
			input: input{
				env: map[string]string{
					"TITUS_IAM_ROLE": "arn:aws:iam::0:role/HackerRole",
				},
				annotations: map[string]string{
					podCommon.AnnotationKeyIAMRole: "arn:aws:iam::0:role/RealRole",
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
				env: map[string]string{
					"EC2_OWNER_ID": "good",
				},
				annotations: map[string]string{
					podCommon.AnnotationKeyNetworkAccountID: "default",
				},
			},
			want: map[string]string{
				"EC2_OWNER_ID": "good",
			},
		},
		{
			name: "FallbackToAccountIDParam",
			input: input{
				annotations: map[string]string{
					podCommon.AnnotationKeyNetworkAccountID: "default",
				},
			},
			want: map[string]string{
				"EC2_OWNER_ID": "default",
			},
		},
		{
			name: "FallbackToConfig",
			input: input{
				env:         map[string]string{},
				annotations: map[string]string{},
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

func TestPodContainerServiceMeshEnabled(t *testing.T) {
	imgName := "titusoss/test-svcmesh:latest"
	config := config.Config{
		ContainerServiceMeshEnabled: true,
	}

	pod, _, err := PodContainerTestArgs()
	assert.NilError(t, err)

	addPodAnnotations(pod, map[string]string{
		podCommon.AnnotationKeyServicePrefix + "/servicemesh.v1.enabled": True,
		podCommon.AnnotationKeyServicePrefix + "/servicemesh.v1.image":   imgName,
	})

	c, err := NewPodContainer(pod, config)
	assert.NilError(t, err)
	assert.Equal(t, c.ServiceMeshEnabled(), true)
	scConfs, err := c.SidecarConfigs()
	assert.NilError(t, err)
	var svcMeshConf *ServiceOpts
	for s := range scConfs {
		if scConfs[s].ServiceName == SidecarServiceServiceMesh {
			svcMeshConf = scConfs[s]
			break
		}
	}
	assert.Assert(t, svcMeshConf != nil)
	assert.Equal(t, svcMeshConf.Image, imgName) // nolint:staticcheck
}

func TestPodContainerServiceMeshEnabledWithConfig(t *testing.T) {
	// If service mesh is set to enabled, but neither the `ProxydServiceImage` config value
	// or the passhtrough property are set, service mesh should end up disabled
	config := config.Config{
		ContainerServiceMeshEnabled: true,
	}

	pod, _, err := PodContainerTestArgs()
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, config)
	assert.NilError(t, err)
	assert.Equal(t, c.ServiceMeshEnabled(), false)
	scConfs, err := c.SidecarConfigs()
	assert.NilError(t, err)
	var svcMeshConf *ServiceOpts
	for s := range scConfs {
		if scConfs[s].ServiceName == SidecarServiceServiceMesh {
			svcMeshConf = scConfs[s]
			break
		}
	}
	assert.Assert(t, svcMeshConf != nil)
	assert.Equal(t, svcMeshConf.Image, "") // nolint:staticcheck
}

func TestPodContainerServiceMeshEnabledWithEmptyConfigValue(t *testing.T) {
	// Setting proxyd image to the empty string should result servicemesh being disabled
	config := config.Config{
		ContainerServiceMeshEnabled: true,
		ProxydServiceImage:          "",
	}

	pod, _, err := PodContainerTestArgs()
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, config)
	assert.NilError(t, err)
	assert.Equal(t, c.ServiceMeshEnabled(), false)
	scConfs, err := c.SidecarConfigs()
	assert.NilError(t, err)
	var svcMeshConf *ServiceOpts
	for s := range scConfs {
		if scConfs[s].ServiceName == SidecarServiceServiceMesh {
			svcMeshConf = scConfs[s]
			break
		}
	}
	assert.Assert(t, svcMeshConf != nil)
	assert.Equal(t, svcMeshConf.Image, "") // nolint:staticcheck
}

func TestPodContainerSubnetIDHasSpaces(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	addPodAnnotations(pod, map[string]string{
		podCommon.AnnotationKeyNetworkSubnetIDs: "subnet-foo, subnet-bar ",
	})
	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)

	expSubnets := []string{"subnet-foo", "subnet-bar"}
	assert.DeepEqual(t, c.SubnetIDs(), &expSubnets)
}

func TestIsEFSID(t *testing.T) {
	var actual bool
	actual, _ = isEFSID("fs-123450")
	assert.Equal(t, actual, true)

	actual, _ = isEFSID("fs-123450.efs.us-west-1.amazonaws.com")
	assert.Equal(t, actual, false)

	actual, _ = isEFSID("nfs.example.com")
	assert.Equal(t, actual, false)
}

func TestPodContainerCustomCmd(t *testing.T) {
	t.Run("WithNilEntrypoint", testPodCustomCmdWithEntrypoint(nil))
	t.Run("WithEmptyEntrypoint", testPodCustomCmdWithEntrypoint([]string{}))
	t.Run("WithEntrypoint", testPodCustomCmdWithEntrypoint([]string{"/bin/sh", "-c"}))
}

func testPodCustomCmdWithEntrypoint(entrypoint []string) func(*testing.T) {
	return func(t *testing.T) {
		pod, conf, err := PodContainerTestArgs()
		assert.NilError(t, err)

		// k8s `Command` is the same as docker's Entrypoint
		pod.Spec.Containers[0].Command = entrypoint
		// k8s `Args` is the same as docker's Command
		pod.Spec.Containers[0].Args = []string{"sleep", "1"}

		c, err := NewPodContainer(pod, *conf)
		assert.NilError(t, err)

		entry, cmd := c.Process()
		assert.Equal(t, len(entry), len(entrypoint))
		assert.Equal(t, len(cmd), 2)
		assert.Equal(t, cmd[0], "sleep")
		assert.Equal(t, cmd[1], "1")
	}
}

func TestPodContainerDefaultProcessIsEmpty(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)

	entrypoint, cmd := c.Process()
	assert.Equal(t, len(entrypoint), 0)
	assert.Equal(t, len(cmd), 0)
}

func TestPodContainerDefaultHostnameStyle(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)

	hostname, err := ComputeHostname(c)
	assert.NilError(t, err)
	assert.Equal(t, c.TaskID(), hostname)
}

func TestPodContainerEC2HostnameStyle(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	pod.Annotations[podCommon.AnnotationKeyPodHostnameStyle] = "ec2"
	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)

	c.SetVPCAllocation(&vpcTypes.HybridAllocation{
		IPV4Address: &vpcapi.UsableAddress{
			PrefixLength: 32,
			Address: &vpcapi.Address{
				Address: "1.2.3.4"},
		},
	})

	hostname, err := ComputeHostname(c)
	assert.NilError(t, err)
	assert.Equal(t, "ip-1-2-3-4", hostname)
}

func TestPodContainerInvalidHostnameStyle(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	pod.Annotations[podCommon.AnnotationKeyPodHostnameStyle] = "foo"
	_, err = NewPodContainer(pod, *conf)
	assert.ErrorContains(t, err, "annotation is not a valid hostname style")
}

func TestPodContainerDefaultIPv6AddressAssignment(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.AssignIPv6Address(), false)
}

func TestPodContainerIPv6AddressAssignment(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	pod.Annotations[podCommon.AnnotationKeyNetworkAssignIPv6Address] = True

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.AssignIPv6Address(), true)
}

func TestPodContainerTtyEnabled(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	pod.Spec.Containers[0].TTY = true

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.TTYEnabled(), true)

	pod.Spec.Containers[0].TTY = false
	c, err = NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.TTYEnabled(), false)
}

func TestPodContainerOomScoreAdj(t *testing.T) {
	pod, conf, err := PodContainerTestArgs()
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	var oomScoreNil *int32
	assert.DeepEqual(t, oomScoreNil, c.OomScoreAdj())

	pod.Annotations[podCommon.AnnotationKeyPodOomScoreAdj] = "99"
	c, err = NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	oomScore := int32(99)

	assert.Equal(t, oomScore, *c.OomScoreAdj())
}

// TODO:
// - log uploading durations
