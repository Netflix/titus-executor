package types

import (
	"fmt"
	"os"
	"regexp"
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

	expImgName := "titusoss/alpine"
	expDigest := "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	expected := "docker.io/" + expImgName + "@" + expDigest

	uc := podCommon.GetUserContainer(pod)
	uc.Image = expected
	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	assert.Equal(t, c.QualifiedImageName(), expected)
	assert.DeepEqual(t, c.ImageName(), ptr.StringPtr(expImgName))
	assert.DeepEqual(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageDigest(), ptr.StringPtr(expDigest))
}

func TestNewPodContainer(t *testing.T) {
	taskID, _, _, pod, conf, err := ContainerTestArgs()
	assert.NilError(t, err)

	ipAddr := "1.2.3.4"
	expectedCommand := []string{"cmd", "arg0", "arg1"}
	expectedEntrypoint := []string{"entrypoint", "arg0", "arg1"}
	iamRole := "arn:aws:iam::0:role/DefaultContainerRole"
	imgName := "titusoss/alpine"
	imgDigest := "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	expectedImage := "docker.io/" + imgName + "@" + imgDigest
	expAppName := "appName"
	expAppOwner := "user@example.com"
	expResources := &Resources{
		CPU:     2,
		GPU:     1,
		Mem:     512,
		Disk:    10000,
		Network: 128,
	}
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
	}
	expBwLimit := int64(128 * units.MB)

	addPodAnnotations(pod, map[string]string{
		podCommon.AnnotationKeyAppName:                  expAppName,
		podCommon.AnnotationKeyAppDetail:                "appDetail",
		podCommon.AnnotationKeyAppOwnerEmail:            expAppOwner,
		podCommon.AnnotationKeyAppStack:                 "appStack",
		podCommon.AnnotationKeyAppSequence:              "appSeq",
		podCommon.AnnotationKeyIAMRole:                  iamRole,
		podCommon.AnnotationKeyJobID:                    "jobid",
		podCommon.AnnotationKeyJobType:                  "service",
		podCommon.AnnotationKeyNetworkAccountID:         "123456",
		podCommon.AnnotationKeyNetworkAssignIPv6Address: "true",
	})

	uc := podCommon.GetUserContainer(pod)
	uc.Args = expectedCommand
	uc.Command = expectedEntrypoint
	uc.Image = expectedImage

	//startTime := time.Now()
	cInfo := &titus.ContainerInfo{
		Process: &titus.ContainerInfo_Process{
			Command:    expectedCommand,
			Entrypoint: expectedEntrypoint,
		},
	}
	err = AddContainerInfoToPod(pod, cInfo)
	assert.NilError(t, err)

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
	expNFSMounts := []NFSMount{
		{
			MountPoint: "/efs1",
			Server:     "fs-abcdef.efs.us-east-1.amazonaws.com",
			ServerPath: "/remote-dir",
			ReadOnly:   true,
		},
	}

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)
	c.SetVPCAllocation(expVPCalloc)

	assert.Equal(t, c.TaskID(), taskID)
	assert.DeepEqual(t, c.IPv4Address(), &ipAddr)
	assert.DeepEqual(t, c.HostnameStyle(), stringNil)

	entrypoint, cmd := c.Process()
	assert.DeepEqual(t, entrypoint, expectedEntrypoint)
	assert.DeepEqual(t, cmd, expectedCommand)

	var int32Nil *int32
	var uint32Nil *uint32
	var capNil *titus.ContainerInfo_Capabilities
	var gpuNil GPUContainer
	var regexpNil *regexp.Regexp
	var metatronCredsNil *titus.ContainerInfo_MetatronCreds
	var stringsNil *[]string

	assert.Equal(t, c.AllowCPUBursting(), false)
	assert.Equal(t, c.AllowNetworkBursting(), false)
	assert.Equal(t, c.AppName(), "appName")
	assert.Equal(t, c.AssignIPv6Address(), true)
	assert.DeepEqual(t, c.BandwidthLimitMbps(), &expBwLimit)
	assert.Equal(t, c.BatchPriority(), stringNil)
	assert.Equal(t, c.Capabilities(), capNil)
	assert.Equal(t, c.CombinedAppStackDetails(), "appName-appStack-appDetail")
	assert.DeepEqual(t, c.NFSMounts(), expNFSMounts)

	expEnv := map[string]string{
		"AWS_METADATA_SERVICE_NUM_ATTEMPTS": "3",
		"AWS_METADATA_SERVICE_TIMEOUT":      "5",
		"EC2_DOMAIN":                        "amazonaws.com",
		"EC2_LOCAL_IPV4":                    "1.2.3.4",
		"EC2_OWNER_ID":                      "123456",
		"EC2_SUBNET_ID":                     "subnet-abcde",
		"EC2_VPC_ID":                        "vpc-abcde",
		"NETFLIX_APP":                       "appName",
		"NETFLIX_APPUSER":                   "appuser",
		"NETFLIX_AUTO_SCALE_GROUP":          "appName-appStack-appDetail-appSeq",
		"NETFLIX_CLUSTER":                   "appName-appStack-appDetail",
		"NETFLIX_DETAIL":                    "appDetail",
		"NETFLIX_STACK":                     "appStack",
		"TITUS_IAM_ROLE":                    iamRole,
		"TITUS_IMAGE_DIGEST":                imgDigest,
		"TITUS_IMAGE_NAME":                  "titusoss/alpine",
		// XXX
		"TITUS_METATRON_ENABLED":      "true",
		"TITUS_NUM_CPU":               "2",
		"TITUS_NUM_DISK":              "10000",
		"TITUS_NUM_MEM":               "512",
		"TITUS_NUM_NETWORK_BANDWIDTH": "128",
		"TITUS_OCI_RUNTIME":           DefaultOciRuntime,
		"EC2_INTERFACE_ID":            "eni-abcde",
	}

	expEnvArray := []string{}
	for k, v := range expEnv {
		expEnvArray = append(expEnvArray, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(expEnvArray)

	assert.DeepEqual(t, c.Env(), expEnv)
	assert.DeepEqual(t, c.SortedEnvArray(), expEnvArray)

	assert.Equal(t, c.ElasticIPPool(), stringNil)
	assert.Equal(t, c.ElasticIPs(), stringNil)
	assert.Equal(t, c.FuseEnabled(), false)
	assert.Equal(t, c.GPUInfo(), gpuNil)
	assert.DeepEqual(t, c.IamRole(), ptr.StringPtr(iamRole))
	assert.Equal(t, c.ID(), taskID)
	assert.DeepEqual(t, c.ImageDigest(), ptr.StringPtr(imgDigest))
	assert.DeepEqual(t, c.ImageName(), ptr.StringPtr("titusoss/alpine"))
	assert.Equal(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageTagForMetrics(), map[string]string{})
	assert.Equal(t, c.IsSystemD(), false)
	assert.Equal(t, c.JobGroupDetail(), "appDetail")
	assert.Equal(t, c.JobGroupStack(), "appStack")
	assert.Equal(t, c.JobGroupSequence(), "appSeq")
	assert.DeepEqual(t, c.JobID(), ptr.StringPtr("jobid"))
	assert.DeepEqual(t, c.JobType(), ptr.StringPtr("service"))
	assert.Equal(t, c.KillWaitSeconds(), uint32Nil)
	assert.Equal(t, c.KvmEnabled(), false)
	assert.DeepEqual(t, c.Labels(), map[string]string{
		appNameLabelKey:         expAppName,
		commandLabelKey:         strings.Join(expectedCommand, " "),
		entrypointLabelKey:      strings.Join(expectedEntrypoint, " "),
		ownerEmailLabelKey:      expAppOwner,
		jobTypeLabelKey:         "service",
		cpuLabelKey:             strconv.Itoa(int(expResources.CPU)),
		iamRoleLabelKey:         iamRole,
		memLabelKey:             strconv.Itoa(int(expResources.Mem)),
		diskLabelKey:            strconv.Itoa(int(expResources.Disk)),
		networkLabelKey:         strconv.Itoa(int(expResources.Network)),
		titusTaskInstanceIDKey:  taskID,
		workloadTypeLabelKey:    string(StaticWorkloadType),
		models.ExecutorPidLabel: strconv.Itoa(os.Getpid()),
		models.TaskIDLabel:      taskID,
	})
	assert.Equal(t, c.LogKeepLocalFileAfterUpload(), false)

	expStdioCheckInterval, _ := time.ParseDuration("1m")
	expUploadCheckInterval, _ := time.ParseDuration("15m")
	expUploadThreshold, _ := time.ParseDuration("6h")
	assert.DeepEqual(t, c.LogStdioCheckInterval(), &expStdioCheckInterval)
	assert.DeepEqual(t, c.LogUploadCheckInterval(), &expUploadCheckInterval)
	assert.DeepEqual(t, c.LogUploaderConfig(), &uploader.Config{
		S3WriterRole: "",
		S3BucketName: "",
		S3PathPrefix: "",
	})
	assert.Equal(t, c.LogUploadRegexp(), regexpNil)
	assert.DeepEqual(t, c.LogUploadThresholdTime(), &expUploadThreshold)

	assert.Equal(t, c.MetatronCreds(), metatronCredsNil)
	zero := int(0)
	assert.DeepEqual(t, c.NormalizedENIIndex(), &zero)
	assert.Equal(t, c.OomScoreAdj(), int32Nil)
	assert.Equal(t, c.QualifiedImageName(), expectedImage)

	assert.DeepEqual(t, c.Resources(), expResources)
	assert.DeepEqual(t, c.RequireIMDSToken(), stringNil)
	assert.Equal(t, c.Runtime(), "runc")
	assert.DeepEqual(t, c.SecurityGroupIDs(), stringsNil)
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
