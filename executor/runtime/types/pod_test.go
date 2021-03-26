package types

import (
	"encoding/base64"
	"regexp"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/uploader"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/golang/protobuf/proto" // nolint: staticcheck
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ptr "k8s.io/utils/pointer"
)

var (
	taskID = "taskid"
)

func addContainerInfoToPod(t *testing.T, pod *corev1.Pod, cInfo *titus.ContainerInfo) {
	pObj, err := proto.Marshal(cInfo)
	assert.NilError(t, err)
	b64str := base64.StdEncoding.EncodeToString(pObj)

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["containerInfo"] = b64str
}

func TestNewPodContainer(t *testing.T) {
	ipAddr := "1.2.3.4"
	expectedCommand := []string{"cmd", "arg0", "arg1"}
	expectedEntrypoint := []string{"entrypoint", "arg0", "arg1"}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: taskID,
		},
	}
	cInfo := &titus.ContainerInfo{
		Process: &titus.ContainerInfo_Process{
			Command:    expectedCommand,
			Entrypoint: expectedEntrypoint,
		},
	}
	startTime := time.Now()

	addContainerInfoToPod(t, pod, cInfo)
	c, err := NewPodContainer(pod, &ipAddr)
	assert.NilError(t, err)

	assert.Equal(t, c.TaskID(), taskID)
	assert.Equal(t, c.IPv4Address(), &ipAddr)
	assert.DeepEqual(t, c.HostnameStyle(), ptr.StringPtr(""))

	entrypoint, cmd := c.Process()
	assert.DeepEqual(t, entrypoint, expectedEntrypoint)
	assert.DeepEqual(t, cmd, expectedCommand)

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

	// Fields from the interface that aren't implemented right now
	var intNil *int
	var int32Nil *int32
	var int64Nil *int64
	var uint32Nil *uint32
	var stringNil *string
	var durationNil *time.Duration
	var capNil *titus.ContainerInfo_Capabilities
	var efsNil []*titus.ContainerInfo_EfsConfigInfo
	var gpuNil GPUContainer
	var uploaderConfNil *uploader.Config
	var regexpNil *regexp.Regexp
	var metatronCredsNil *titus.ContainerInfo_MetatronCreds
	var resourcesNil *Resources
	var stringsNil *[]string
	var vpcAllocNil *vpcTypes.HybridAllocation

	assert.Equal(t, c.AllowCPUBursting(), false)
	assert.Equal(t, c.AllowNetworkBursting(), false)
	assert.Equal(t, c.AppName(), "")
	assert.Equal(t, c.AssignIPv6Address(), false)
	assert.Equal(t, c.BandwidthLimitMbps(), int64Nil)
	assert.Equal(t, c.BatchPriority(), stringNil)
	assert.Equal(t, c.Capabilities(), capNil)
	assert.Equal(t, c.CombinedAppStackDetails(), "")
	assert.DeepEqual(t, c.EfsConfigInfo(), efsNil)
	assert.DeepEqual(t, c.Env(), map[string]string{})
	assert.Equal(t, c.ElasticIPPool(), stringNil)
	assert.Equal(t, c.ElasticIPs(), stringNil)
	assert.Equal(t, c.FuseEnabled(), false)
	assert.Equal(t, c.GPUInfo(), gpuNil)
	assert.Equal(t, c.IamRole(), stringNil)
	assert.Equal(t, c.ID(), "")
	assert.Equal(t, c.ImageDigest(), stringNil)
	assert.Equal(t, c.ImageName(), stringNil)
	assert.Equal(t, c.ImageVersion(), stringNil)
	assert.DeepEqual(t, c.ImageTagForMetrics(), map[string]string{})
	assert.Equal(t, c.IsSystemD(), false)
	assert.Equal(t, c.JobGroupDetail(), "")
	assert.Equal(t, c.JobGroupStack(), "")
	assert.Equal(t, c.JobGroupSequence(), "")
	assert.Equal(t, c.JobID(), stringNil)
	assert.Equal(t, c.KillWaitSeconds(), uint32Nil)
	assert.Equal(t, c.KvmEnabled(), false)
	assert.DeepEqual(t, c.Labels(), map[string]string{})
	assert.Equal(t, c.LogKeepLocalFileAfterUpload(), false)
	assert.Equal(t, c.LogStdioCheckInterval(), durationNil)
	assert.Equal(t, c.LogUploadCheckInterval(), durationNil)
	assert.Equal(t, c.LogUploaderConfig(), uploaderConfNil)
	assert.Equal(t, c.LogUploadRegexp(), regexpNil)
	assert.Equal(t, c.LogUploadThresholdTime(), durationNil)
	assert.Equal(t, c.MetatronCreds(), metatronCredsNil)
	assert.Equal(t, c.NormalizedENIIndex(), intNil)
	assert.Equal(t, c.OomScoreAdj(), int32Nil)
	assert.Equal(t, c.QualifiedImageName(), "")
	assert.Equal(t, c.Resources(), resourcesNil)
	assert.Equal(t, c.RequireIMDSToken(), stringNil)
	assert.Equal(t, c.Runtime(), "")
	assert.DeepEqual(t, c.SecurityGroupIDs(), stringsNil)
	assert.Equal(t, c.ServiceMeshEnabled(), false)
	assert.Equal(t, c.ShmSizeMiB(), uint32Nil)

	sidecars, err := c.SidecarConfigs()
	assert.NilError(t, err)
	assert.DeepEqual(t, sidecars, map[string]*ServiceOpts{})

	assert.Equal(t, c.SignedAddressAllocationUUID(), stringNil)
	assert.DeepEqual(t, c.SortedEnvArray(), []string{})
	assert.Equal(t, c.SubnetIDs(), stringNil)
	assert.Equal(t, c.TTYEnabled(), false)
	assert.Equal(t, c.UploadDir("foo"), "")
	assert.Equal(t, c.UseJumboFrames(), false)
	assert.Equal(t, c.VPCAllocation(), vpcAllocNil)
	assert.Equal(t, c.VPCAccountID(), stringNil)
}

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
