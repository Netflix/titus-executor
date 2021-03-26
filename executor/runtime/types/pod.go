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

// Compile-time check that PodContainer implements the Container interface:
var _ Container = (*PodContainer)(nil)

// PodContainer is an implementation of Container backed only by a kubernetes pod.
// This is currently using the base64'ed ContainerInfo until all fields are ported over to annotations
type PodContainer struct {
	command       []string
	entrypoint    []string
	hostnameStyle string
	ipv4Address   *string
	pod           *corev1.Pod
	titusInfo     *titus.ContainerInfo
}

func NewPodContainer(pod *corev1.Pod, ipv4Address *string) (*PodContainer, error) {
	if pod == nil {
		return nil, errors.New("missing pod")
	}
	if ipv4Address == nil {
		return nil, errors.New("missing ipv4 address")
	}

	c := &PodContainer{
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

func (c *PodContainer) AllowCPUBursting() bool {
	return false
}

func (c *PodContainer) AllowNetworkBursting() bool {
	return false
}

func (c *PodContainer) AppName() string {
	return ""
}

func (c *PodContainer) AssignIPv6Address() bool {
	return false
}

func (c *PodContainer) BandwidthLimitMbps() *int64 {
	return nil
}

func (c *PodContainer) BatchPriority() *string {
	return nil
}

func (c *PodContainer) Capabilities() *titus.ContainerInfo_Capabilities {
	return nil
}

func (c *PodContainer) CombinedAppStackDetails() string {
	return ""
}

func (c *PodContainer) ContainerInfo() (*titus.ContainerInfo, error) {
	return c.titusInfo, nil
}

func (c *PodContainer) EBSInfo() EBSInfo {
	return EBSInfo{}
}

func (c *PodContainer) EfsConfigInfo() []*titus.ContainerInfo_EfsConfigInfo {
	return nil
}

func (c *PodContainer) Env() map[string]string {
	return map[string]string{}
}

func (c *PodContainer) ElasticIPPool() *string {
	return nil
}

func (c *PodContainer) ElasticIPs() *string {
	return nil
}

func (c *PodContainer) FuseEnabled() bool {
	return false
}

func (c *PodContainer) GPUInfo() GPUContainer {
	return nil
}

func (c *PodContainer) HostnameStyle() *string {
	return &c.hostnameStyle
}

func (c *PodContainer) IamRole() *string {
	return nil
}

func (c *PodContainer) ID() string {
	return ""
}

func (c *PodContainer) ImageDigest() *string {
	return nil
}

func (c *PodContainer) ImageName() *string {
	return nil
}

func (c *PodContainer) ImageVersion() *string {
	return nil
}

func (c *PodContainer) ImageTagForMetrics() map[string]string {
	return map[string]string{}
}

func (c *PodContainer) IPv4Address() *string {
	return c.ipv4Address
}

func (c *PodContainer) IsSystemD() bool {
	return false
}

func (c *PodContainer) JobGroupDetail() string {
	return ""
}

func (c *PodContainer) JobGroupStack() string {
	return ""
}

func (c *PodContainer) JobGroupSequence() string {
	return ""
}

func (c *PodContainer) JobID() *string {
	return nil
}

func (c *PodContainer) KillWaitSeconds() *uint32 {
	return nil
}

func (c *PodContainer) KvmEnabled() bool {
	return false
}

func (c *PodContainer) Labels() map[string]string {
	return map[string]string{}
}

func (c *PodContainer) LogKeepLocalFileAfterUpload() bool {
	return false
}

func (c *PodContainer) LogStdioCheckInterval() *time.Duration {
	return nil
}

func (c *PodContainer) LogUploadCheckInterval() *time.Duration {
	return nil
}

func (c *PodContainer) LogUploaderConfig() *uploader.Config {
	return nil
}

func (c *PodContainer) LogUploadRegexp() *regexp.Regexp {
	return nil
}

func (c *PodContainer) LogUploadThresholdTime() *time.Duration {
	return nil
}

func (c *PodContainer) MetatronCreds() *titus.ContainerInfo_MetatronCreds {
	return nil
}

func (c *PodContainer) NormalizedENIIndex() *int {
	return nil
}

func (c *PodContainer) OomScoreAdj() *int32 {
	return nil
}

func (c *PodContainer) Process() ([]string, []string) {
	return c.entrypoint, c.command
}

func (c *PodContainer) QualifiedImageName() string {
	return ""
}

func (c *PodContainer) Resources() *Resources {
	return nil
}

func (c *PodContainer) RequireIMDSToken() *string {
	return nil
}

func (c *PodContainer) Runtime() string {
	return ""
}

func (c *PodContainer) SeccompAgentEnabledForNetSyscalls() bool {
	return false
}

func (c *PodContainer) SeccompAgentEnabledForPerfSyscalls() bool {
	return false
}

func (c *PodContainer) SecurityGroupIDs() *[]string {
	return nil
}

func (c *PodContainer) ServiceMeshEnabled() bool {
	return false
}

func (c *PodContainer) SetEnv(string, string) {
}

func (c *PodContainer) SetEnvs(env map[string]string) {
}

func (c *PodContainer) SetGPUInfo(GPUContainer) {
}

func (c *PodContainer) SetID(string) {
}

func (c *PodContainer) SetSystemD(bool) {
}

func (c *PodContainer) SetVPCAllocation(*vpcTypes.HybridAllocation) {
}

func (c *PodContainer) ShmSizeMiB() *uint32 {
	return nil
}

func (c *PodContainer) SidecarConfigs() (map[string]*ServiceOpts, error) {
	return map[string]*ServiceOpts{}, nil
}

func (c *PodContainer) SignedAddressAllocationUUID() *string {
	return nil
}

func (c *PodContainer) SortedEnvArray() []string {
	return []string{}
}

func (c *PodContainer) SubnetIDs() *string {
	return nil
}

func (c *PodContainer) TaskID() string {
	return c.pod.Name
}

func (c *PodContainer) TTYEnabled() bool {
	return false
}

func (c *PodContainer) UploadDir(string) string {
	return ""
}

func (c *PodContainer) UseJumboFrames() bool {
	return false
}

func (c *PodContainer) VPCAllocation() *vpcTypes.HybridAllocation {
	return nil
}

func (c *PodContainer) VPCAccountID() *string {
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
