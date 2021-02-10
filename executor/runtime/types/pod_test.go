package types

import (
	"fmt"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/uploader"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types" // nolint: staticcheck
	podCommon "github.com/Netflix/titus-kube-common/pod"   // nolint: staticcheck
	resourceCommon "github.com/Netflix/titus-kube-common/resource"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ptr "k8s.io/utils/pointer"
)

func TestNewPodContainer(t *testing.T) {
	var stringNil *string
	//taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	taskID, _, _, conf, err := ContainerTestArgs()
	assert.NilError(t, err)

	ipAddr := "1.2.3.4"
	expectedCommand := []string{"cmd", "arg0", "arg1"}
	expectedEntrypoint := []string{"entrypoint", "arg0", "arg1"}

	cpu := resource.NewQuantity(1, resource.DecimalSI)
	gpu := resource.NewQuantity(1, resource.DecimalSI)
	mem, _ := resource.ParseQuantity("512Mi")
	disk, _ := resource.ParseQuantity("10000Mi")
	network, _ := resource.ParseQuantity("128M")
	iamRole := "arn:aws:iam::0:role/DefaultContainerRole"
	imgName := "titusoss/alpine"
	imgDigest := "sha256:58e1a1bb75db1b5a24a462dd5e2915277ea06438c3f105138f97eb53149673c4"
	expectedImage := "docker.io/" + imgName + "@" + imgDigest

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: taskID,
			Annotations: map[string]string{
				podCommon.AnnotationKeyPodSchemaVersion: "1",

				podCommon.AnnotationKeyAppName:          "appName",
				podCommon.AnnotationKeyAppDetail:        "appDetail",
				podCommon.AnnotationKeyAppStack:         "appStack",
				podCommon.AnnotationKeyAppSequence:      "appSeq",
				podCommon.AnnotationKeyIAMRole:          iamRole,
				podCommon.AnnotationKeyNetworkAccountID: "123456",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:    taskID,
					Command: expectedEntrypoint,
					Image:   expectedImage,
					Args:    expectedCommand,
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:                 *cpu,
							corev1.ResourceMemory:              mem,
							corev1.ResourceEphemeralStorage:    disk,
							resourceCommon.ResourceNameGpu:     *gpu,
							resourceCommon.ResourceNameNetwork: network,
						},
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:                 *cpu,
							corev1.ResourceMemory:              mem,
							corev1.ResourceEphemeralStorage:    disk,
							resourceCommon.ResourceNameGpu:     *gpu,
							resourceCommon.ResourceNameNetwork: network,
						},
					},
				},
			},
		},
	}
	//startTime := time.Now()
	cInfo := &titus.ContainerInfo{
		Process: &titus.ContainerInfo_Process{
			Command:    expectedCommand,
			Entrypoint: expectedEntrypoint,
		},
	}
	err = AddContainerInfoToPod(pod, cInfo)
	assert.NilError(t, err)

	c, err := NewPodContainer(pod, *conf)
	assert.NilError(t, err)

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
	c.SetVPCAllocation(expVPCalloc)

	assert.Equal(t, c.TaskID(), taskID)
	assert.DeepEqual(t, c.IPv4Address(), &ipAddr)
	assert.DeepEqual(t, c.HostnameStyle(), stringNil)

	entrypoint, cmd := c.Process()
	assert.DeepEqual(t, entrypoint, expectedEntrypoint)
	assert.DeepEqual(t, cmd, expectedCommand)

	/*
		// XXX
		actCinfo, err := c.ContainerInfo()
		assert.NilError(t, err)
		assert.Assert(t, proto.Equal(cInfo, actCinfo))

		cConf, err := ContainerConfig(c, startTime)
		assert.NilError(t, err)
		assert.Assert(t, cConf != nil)

		launchTime := uint64(startTime.Unix())
		cInfo.RunState = &titus.RunningContainerInfo{
			LaunchTimeUnixSec: &launchTime,
			TaskId:            &taskID,
			HostName:          &taskID,
		}
		assert.Assert(t, cConf.RunState != nil) // nolint: staticcheck
		assert.Assert(t, proto.Equal(cInfo, cConf))
	*/

	// Fields from the interface that aren't implemented right now
	var intNil *int
	var int32Nil *int32
	var int64Nil *int64
	var uint32Nil *uint32
	var capNil *titus.ContainerInfo_Capabilities
	var efsNil []*titus.ContainerInfo_EfsConfigInfo
	var gpuNil GPUContainer
	var regexpNil *regexp.Regexp
	var metatronCredsNil *titus.ContainerInfo_MetatronCreds
	var stringsNil *[]string

	assert.Equal(t, c.AllowCPUBursting(), false)
	assert.Equal(t, c.AllowNetworkBursting(), false)
	assert.Equal(t, c.AppName(), "appName")
	assert.Equal(t, c.AssignIPv6Address(), false)
	assert.Equal(t, c.BandwidthLimitMbps(), int64Nil)
	assert.Equal(t, c.BatchPriority(), stringNil)
	assert.Equal(t, c.Capabilities(), capNil)
	assert.Equal(t, c.CombinedAppStackDetails(), "appName-appStack-appDetail")
	assert.DeepEqual(t, c.EfsConfigInfo(), efsNil)

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
		"TITUS_METATRON_ENABLED":            "true",
		"TITUS_NUM_CPU":                     "1",
		"TITUS_NUM_DISK":                    "10000",
		"TITUS_NUM_MEM":                     "512",
		"TITUS_NUM_NETWORK_BANDWIDTH":       "128",
		"TITUS_OCI_RUNTIME":                 DefaultOciRuntime,
		"EC2_INTERFACE_ID":                  "eni-abcde",
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
	assert.Equal(t, c.ID(), "")
	assert.DeepEqual(t, c.ImageDigest(), ptr.StringPtr(imgDigest))
	assert.Equal(t, c.ImageName(), stringNil)
	assert.Equal(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageTagForMetrics(), map[string]string{})
	assert.Equal(t, c.IsSystemD(), false)
	assert.Equal(t, c.JobGroupDetail(), "appDetail")
	assert.Equal(t, c.JobGroupStack(), "appStack")
	assert.Equal(t, c.JobGroupSequence(), "appSeq")
	assert.Equal(t, c.JobID(), stringNil)
	assert.Equal(t, c.KillWaitSeconds(), uint32Nil)
	assert.Equal(t, c.KvmEnabled(), false)
	assert.DeepEqual(t, c.Labels(), map[string]string{})
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
	assert.Equal(t, c.NormalizedENIIndex(), intNil)
	assert.Equal(t, c.OomScoreAdj(), int32Nil)
	assert.Equal(t, c.QualifiedImageName(), expectedImage)

	assert.DeepEqual(t, c.Resources(), &Resources{
		CPU:     1,
		GPU:     1,
		Mem:     512,
		Disk:    10000,
		Network: 128,
	})
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
