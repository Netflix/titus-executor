package types

import (
	"encoding/base64"
	"regexp"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/uploader"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
)

// Compile-time check that PodContainerInfoContainer implements the Container interface:
var _ Container = (*PodContainerInfoContainer)(nil)

// PodContainerInfoContainer is an implementation of Container backed only by a kubernetes pod.
// This is currently using the base64'ed ContainerInfo until all fields are ported over to annotations
type PodContainerInfoContainer struct {
	command       []string
	entrypoint    []string
	hostnameStyle string
	ipv4Address   *string
	pod           *corev1.Pod
	titusInfo     *titus.ContainerInfo
}

func AddContainerInfoToPod(pod *corev1.Pod, cInfo *titus.ContainerInfo) error {
	pObj, err := proto.Marshal(cInfo)
	if err != nil {
		return err
	}

	b64str := base64.StdEncoding.EncodeToString(pObj)

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations["containerInfo"] = b64str
	return nil
}

func NewPodContainerInfoContainer(pod *corev1.Pod, ipv4Address *string) (*PodContainerInfoContainer, error) {
	if pod == nil {
		return nil, errors.New("missing pod")
	}
	if ipv4Address == nil {
		return nil, errors.New("missing ipv4 address")
	}

	c := &PodContainerInfoContainer{
		ipv4Address: ipv4Address,
		pod:         pod,
	}
	cInfo, err := extractContainerInfoFromPod(pod)
	if err != nil {
		return nil, err
	}
	c.titusInfo = cInfo

	if val, ok := c.titusInfo.GetPassthroughAttributes()[hostnameStyleParam]; ok {
		if err := validateHostnameStyle(val); err != nil {
			return nil, err
		}

		c.hostnameStyle = val
	}

	entrypoint, command, err := parseEntryPointAndCommand(c.titusInfo)
	if err != nil {
		return nil, err
	}
	if entrypoint != nil {
		c.entrypoint = entrypoint
	}
	if command != nil {
		c.command = command
	}

	return c, nil
}

func (c *PodContainerInfoContainer) AllowCPUBursting() bool {
	return false
}

func (c *PodContainerInfoContainer) AllowNetworkBursting() bool {
	return false
}

func (c *PodContainerInfoContainer) AppArmorProfile() *string {
	return nil
}

func (c *PodContainerInfoContainer) AppName() string {
	return ""
}

func (c *PodContainerInfoContainer) AssignIPv6Address() bool {
	return false
}

func (c *PodContainerInfoContainer) BandwidthLimitMbps() *int64 {
	return nil
}

func (c *PodContainerInfoContainer) BatchPriority() *string {
	return nil
}

func (c *PodContainerInfoContainer) Capabilities() *titus.ContainerInfo_Capabilities {
	return nil
}

func (c *PodContainerInfoContainer) CombinedAppStackDetails() string {
	return ""
}

func (c *PodContainerInfoContainer) ContainerInfo() (*titus.ContainerInfo, error) {
	return c.titusInfo, nil
}

func (c *PodContainerInfoContainer) EfsConfigInfo() []*titus.ContainerInfo_EfsConfigInfo {
	return nil
}

func (c *PodContainerInfoContainer) Env() map[string]string {
	return map[string]string{}
}

func (c *PodContainerInfoContainer) EnvOverrides() map[string]string {
	return map[string]string{}
}

func (c *PodContainerInfoContainer) ElasticIPPool() *string {
	return nil
}

func (c *PodContainerInfoContainer) ElasticIPs() *string {
	return nil
}

func (c *PodContainerInfoContainer) FuseEnabled() bool {
	return false
}

func (c *PodContainerInfoContainer) GPUInfo() GPUContainer {
	return nil
}

func (c *PodContainerInfoContainer) HostnameStyle() *string {
	return &c.hostnameStyle
}

func (c *PodContainerInfoContainer) IamRole() *string {
	return nil
}

func (c *PodContainerInfoContainer) ID() string {
	return ""
}

func (c *PodContainerInfoContainer) ImageDigest() *string {
	return nil
}

func (c *PodContainerInfoContainer) ImageName() *string {
	return nil
}

func (c *PodContainerInfoContainer) ImageVersion() *string {
	return nil
}

func (c *PodContainerInfoContainer) ImageTagForMetrics() map[string]string {
	return map[string]string{}
}

func (c *PodContainerInfoContainer) IPv4Address() *string {
	return c.ipv4Address
}

func (c *PodContainerInfoContainer) IsSystemD() bool {
	return false
}

func (c *PodContainerInfoContainer) JobGroupDetail() string {
	return ""
}

func (c *PodContainerInfoContainer) JobGroupStack() string {
	return ""
}

func (c *PodContainerInfoContainer) JobGroupSequence() string {
	return ""
}

func (c *PodContainerInfoContainer) JobID() *string {
	return nil
}

func (c *PodContainerInfoContainer) JobType() *string {
	return nil
}

func (c *PodContainerInfoContainer) KillWaitSeconds() *uint32 {
	return nil
}

func (c *PodContainerInfoContainer) KvmEnabled() bool {
	return false
}

func (c *PodContainerInfoContainer) Labels() map[string]string {
	return map[string]string{}
}

func (c *PodContainerInfoContainer) LogKeepLocalFileAfterUpload() bool {
	return false
}

func (c *PodContainerInfoContainer) LogStdioCheckInterval() *time.Duration {
	return nil
}

func (c *PodContainerInfoContainer) LogUploadCheckInterval() *time.Duration {
	return nil
}

func (c *PodContainerInfoContainer) LogUploaderConfig() *uploader.Config {
	return nil
}

func (c *PodContainerInfoContainer) LogUploadRegexp() *regexp.Regexp {
	return nil
}

func (c *PodContainerInfoContainer) LogUploadThresholdTime() *time.Duration {
	return nil
}

func (c *PodContainerInfoContainer) MetatronCreds() *titus.ContainerInfo_MetatronCreds {
	return nil
}

func (c *PodContainerInfoContainer) NormalizedENIIndex() *int {
	return nil
}

func (c *PodContainerInfoContainer) OomScoreAdj() *int32 {
	return nil
}

func (c *PodContainerInfoContainer) OwnerEmail() *string {
	return nil
}

func (c *PodContainerInfoContainer) Process() ([]string, []string) {
	return c.entrypoint, c.command
}

func (c *PodContainerInfoContainer) QualifiedImageName() string {
	return ""
}

func (c *PodContainerInfoContainer) Resources() *Resources {
	return nil
}

func (c *PodContainerInfoContainer) RequireIMDSToken() *string {
	return nil
}

func (c *PodContainerInfoContainer) Runtime() string {
	return ""
}

func (c *PodContainerInfoContainer) SeccompAgentEnabledForPerfSyscalls() bool {
	return false
}

func (c *PodContainerInfoContainer) SecurityGroupIDs() *[]string {
	return nil
}

func (c *PodContainerInfoContainer) ServiceMeshEnabled() bool {
	return false
}

func (c *PodContainerInfoContainer) SetEnv(string, string) {
}

func (c *PodContainerInfoContainer) SetEnvs(env map[string]string) {
}

func (c *PodContainerInfoContainer) SetGPUInfo(GPUContainer) {
}

func (c *PodContainerInfoContainer) SetID(string) {
}

func (c *PodContainerInfoContainer) SetSystemD(bool) {
}

func (c *PodContainerInfoContainer) SetVPCAllocation(*vpcTypes.HybridAllocation) {
}

func (c *PodContainerInfoContainer) ShmSizeMiB() *uint32 {
	return nil
}

func (c *PodContainerInfoContainer) SidecarConfigs() (map[string]*SidecarContainerConfig, error) {
	return map[string]*SidecarContainerConfig{}, nil
}

func (c *PodContainerInfoContainer) SignedAddressAllocationUUID() *string {
	return nil
}

func (c *PodContainerInfoContainer) SortedEnvArray() []string {
	return []string{}
}

func (c *PodContainerInfoContainer) SubnetIDs() *string {
	return nil
}

func (c *PodContainerInfoContainer) TaskID() string {
	return c.pod.Name
}

func (c *PodContainerInfoContainer) TTYEnabled() bool {
	return false
}

func (c *PodContainerInfoContainer) UploadDir(string) string {
	return ""
}

func (c *PodContainerInfoContainer) UseJumboFrames() bool {
	return false
}

func (c *PodContainerInfoContainer) VPCAllocation() *vpcTypes.HybridAllocation {
	return nil
}

func (c *PodContainerInfoContainer) VPCAccountID() *string {
	return nil
}

func extractContainerInfoFromPod(pod *corev1.Pod) (*titus.ContainerInfo, error) {
	str, ok := pod.GetAnnotations()["containerInfo"]
	if !ok {
		return nil, errors.New("unable to find containerInfo annotation")
	}

	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, errors.Wrap(err, "unable to base64 decode containerInfo annotation")
	}

	var cInfo titus.ContainerInfo
	err = proto.Unmarshal(data, &cInfo)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decode containerInfo protobuf")
	}

	return &cInfo, nil
}
