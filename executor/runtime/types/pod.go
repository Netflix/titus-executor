package types

import (
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/uploader"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	resourceCommon "github.com/Netflix/titus-kube-common/resource"
	"github.com/docker/distribution/reference"
	units "github.com/docker/go-units"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/maps"
)

// Compile-time check that PodContainer implements the Container interface:
var _ Container = (*PodContainer)(nil)

// PodContainer is an implementation of Container backed only by a kubernetes pod.
// This is currently using the base64'ed ContainerInfo until all fields are ported over to annotations
type PodContainer struct {
	config         config.Config
	containerImage reference.Reference
	envLock        sync.Mutex
	// envOverrides are set by the executor for things like IPv4 / IPv6 address
	envOverrides map[string]string
	// ID is the container ID (in Docker). It is set by the container runtime after starting up.
	id    string
	image string
	// Is this container meant to run SystemD?
	isSystemD bool
	// GPU devices
	gpuInfo           GPUContainer
	labels            map[string]string
	logUploaderConfig *uploader.Config
	pod               *corev1.Pod
	podConfig         *podCommon.Config
	resources         *Resources
	titusInfo         *titus.ContainerInfo
	// userEnv is the environment passed in by the user in the pod spec
	userEnv       map[string]string
	vpcAllocation vpcTypes.HybridAllocation
}

func NewPodContainer(pod *corev1.Pod, cfg config.Config) (*PodContainer, error) {
	if pod == nil {
		return nil, errors.New("missing pod")
	}

	pConf, err := podCommon.PodToConfig(pod)
	if err != nil {
		return nil, err
	}

	// XXX: maybe error out if things don't look right?
	userContainer := podCommon.GetUserContainer(pod)
	resources, err := getContainerResources(userContainer)
	if err != nil {
		return nil, err
	}

	userEnv := map[string]string{}
	for _, envVar := range userContainer.Env {
		userEnv[envVar.Name] = userEnv[envVar.Value]
	}

	cInfo, err := extractContainerInfoFromPod(pod)
	if err != nil {
		return nil, err
	}

	imgRef, err := reference.Parse(userContainer.Image)
	if err != nil {
		return nil, fmt.Errorf("error parsing docker image \"%s\" for container \"%s\": %w", userContainer.Image, userContainer.Name, err)
	}

	c := &PodContainer{
		config:            cfg,
		containerImage:    imgRef,
		envOverrides:      map[string]string{},
		id:                pod.Name,
		image:             userContainer.Image,
		logUploaderConfig: createLogUploadConfig(pConf),
		pod:               pod,
		podConfig:         pConf,
		resources:         resources,
		titusInfo:         cInfo,
		userEnv:           userEnv,
	}

	c.labels = addLabels(c.id, c, resources)
	return c, nil
}

func (c *PodContainer) AllowCPUBursting() bool {
	return false
}

func (c *PodContainer) AllowNetworkBursting() bool {
	return false
}

func (c *PodContainer) AppArmorProfile() *string {
	return c.podConfig.AppArmorProfile
}

func (c *PodContainer) AppName() string {
	if c.podConfig.AppName != nil {
		return *c.podConfig.AppName
	}
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
	return combinedAppStackDetails(c)
}

func (c *PodContainer) ContainerInfo() (*titus.ContainerInfo, error) {
	// TODO: this needs to be removed once Metatron supports pods
	return c.titusInfo, nil
}

func (c *PodContainer) EfsConfigInfo() []*titus.ContainerInfo_EfsConfigInfo {
	return nil
}

func (c *PodContainer) Env() map[string]string {
	return populateContainerEnv(c, c.config, c.userEnv)
}

func (c *PodContainer) EnvOverrides() map[string]string {
	c.envLock.Lock()
	envOverrides := maps.CopySS(c.envOverrides)
	c.envLock.Unlock()
	return envOverrides
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
	return c.gpuInfo
}

func (c *PodContainer) HostnameStyle() *string {
	return c.podConfig.HostnameStyle
}

func (c *PodContainer) IamRole() *string {
	return c.podConfig.IAMRole
}

func (c *PodContainer) ID() string {
	return c.id
}

func (c *PodContainer) ImageDigest() *string {
	digest, ok := c.containerImage.(reference.Digested)
	if !ok {
		return nil
	}

	digestStr := digest.Digest().String()
	return &digestStr
}

func (c *PodContainer) ImageName() *string {
	name, ok := c.containerImage.(reference.Named)
	if !ok {
		return nil
	}

	nameStr := reference.FamiliarName(name)
	return &nameStr
}

func (c *PodContainer) ImageVersion() *string {
	tag, ok := c.containerImage.(reference.Tagged)
	if !ok {
		return nil
	}

	tagStr := tag.Tag()
	return &tagStr
}

func (c *PodContainer) ImageTagForMetrics() map[string]string {
	return map[string]string{}
}

func (c *PodContainer) IPv4Address() *string {
	if c.vpcAllocation.IPV4Address == nil {
		return nil
	}

	return &c.vpcAllocation.IPV4Address.Address.Address
}

func (c *PodContainer) IsSystemD() bool {
	return c.isSystemD
}

func (c *PodContainer) JobGroupDetail() string {
	if c.podConfig.AppDetail != nil {
		return *c.podConfig.AppDetail
	}
	return ""
}

func (c *PodContainer) JobGroupStack() string {
	if c.podConfig.AppStack != nil {
		return *c.podConfig.AppStack
	}
	return ""
}

func (c *PodContainer) JobGroupSequence() string {
	if c.podConfig.AppSequence != nil {
		return *c.podConfig.AppSequence
	}
	return ""
}

func (c *PodContainer) JobID() *string {
	return c.podConfig.JobID
}

func (c *PodContainer) JobType() *string {
	return c.podConfig.JobType
}

func (c *PodContainer) KillWaitSeconds() *uint32 {
	return nil
}

func (c *PodContainer) KvmEnabled() bool {
	return false
}

func (c *PodContainer) Labels() map[string]string {
	return c.labels
}

func (c *PodContainer) LogKeepLocalFileAfterUpload() bool {
	if c.podConfig.LogKeepLocalFile != nil {
		return *c.podConfig.LogKeepLocalFile
	}
	return false
}

func (c *PodContainer) LogStdioCheckInterval() *time.Duration {
	if c.podConfig.LogStdioCheckInterval != nil {
		return c.podConfig.LogStdioCheckInterval
	}
	return &defaultStdioLogCheckInterval
}

func (c *PodContainer) LogUploadCheckInterval() *time.Duration {
	if c.podConfig.LogUploadCheckInterval != nil {
		return c.podConfig.LogUploadCheckInterval
	}
	return &defaultLogUploadCheckInterval
}

func (c *PodContainer) LogUploaderConfig() *uploader.Config {
	return c.logUploaderConfig
}

func (c *PodContainer) LogUploadRegexp() *regexp.Regexp {
	return c.podConfig.LogUploadRegExp
}

func (c *PodContainer) LogUploadThresholdTime() *time.Duration {
	if c.podConfig.LogUploadThresholdTime != nil {
		return c.podConfig.LogUploadThresholdTime
	}
	return &defaultLogUploadThresholdTime
}

func (c *PodContainer) MetatronCreds() *titus.ContainerInfo_MetatronCreds {
	return c.titusInfo.GetMetatronCreds()
}

func (c *PodContainer) NormalizedENIIndex() *int {
	// This is unused in the v3 vpc service
	unused := int(0)
	return &unused
}

func (c *PodContainer) OomScoreAdj() *int32 {
	return nil
}

func (c *PodContainer) OwnerEmail() *string {
	return c.podConfig.AppOwnerEmail
}

func (c *PodContainer) Process() ([]string, []string) {
	uc := podCommon.GetUserContainer(c.pod)
	return uc.Command, uc.Args
}

func (c *PodContainer) QualifiedImageName() string {
	return c.image
}

func (c *PodContainer) Resources() *Resources {
	return c.resources
}

func (c *PodContainer) RequireIMDSToken() *string {
	return nil
}

func (c *PodContainer) Runtime() string {
	if c.gpuInfo != nil {
		return c.gpuInfo.Runtime()
	}
	return DefaultOciRuntime
}

func (c *PodContainer) SeccompAgentEnabledForNetSyscalls() bool {
	return false
}

func (c *PodContainer) SeccompAgentEnabledForPerfSyscalls() bool {
	return false
}

func (c *PodContainer) SecurityGroupIDs() *[]string {
	return c.podConfig.SecurityGroupIDs
}

func (c *PodContainer) ServiceMeshEnabled() bool {
	return false
}

func (c *PodContainer) SetEnv(key, value string) {
	c.envLock.Lock()
	defer c.envLock.Unlock()
	c.envOverrides[key] = value
}

func (c *PodContainer) SetEnvs(env map[string]string) {
	c.envLock.Lock()
	defer c.envLock.Unlock()
	for key, value := range env {
		c.envOverrides[key] = value
	}
}

func (c *PodContainer) SetGPUInfo(gpuInfo GPUContainer) {
	c.gpuInfo = gpuInfo
}

func (c *PodContainer) SetID(id string) {
	c.id = id
	c.SetEnv(titusContainerIDEnvVariableName, id)
}

func (c *PodContainer) SetSystemD(isSystemD bool) {
	c.isSystemD = isSystemD
}

func (c *PodContainer) SetVPCAllocation(allocation *vpcTypes.HybridAllocation) {
	c.vpcAllocation = *allocation
}

func (c *PodContainer) ShmSizeMiB() *uint32 {
	return nil
}

func (c *PodContainer) SidecarConfigs() (map[string]*SidecarContainerConfig, error) {
	scMap := make(map[string]*SidecarContainerConfig)
	svcMeshImage := ""
	if c.ServiceMeshEnabled() {
		// XXX
		/*
			img, err := c.serviceMeshImageName()
			if err != nil {
				return scMap, err
			}
			svcMeshImage = img
		*/
		svcMeshImage = "foo"
	}

	imageMap := map[string]string{
		SidecarServiceAbMetrix:    c.config.AbmetrixServiceImage,
		SidecarServiceLogViewer:   c.config.LogViewerServiceImage,
		SidecarServiceMetatron:    c.config.MetatronServiceImage,
		SidecarServiceServiceMesh: svcMeshImage,
		SidecarServiceSshd:        c.config.SSHDServiceImage,
		SidecarServiceSpectatord:  c.config.SpectatordServiceImage,
	}

	for _, sc := range sideCars {
		imgName := imageMap[sc.ServiceName]
		if imgName != "" {
			sc.Image = path.Join(c.config.DockerRegistry, imgName)
		}

		scAddr := sc
		scMap[sc.ServiceName] = &scAddr
	}

	return scMap, nil
}

func (c *PodContainer) SignedAddressAllocationUUID() *string {
	return nil
}

func (c *PodContainer) SortedEnvArray() []string {
	return sortedEnv(c.Env())
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

func (c *PodContainer) UploadDir(namespace string) string {
	return filepath.Join("titan", c.config.Stack, namespace, c.TaskID())
}

func (c *PodContainer) UseJumboFrames() bool {
	return false
}

func (c *PodContainer) VPCAllocation() *vpcTypes.HybridAllocation {
	return &c.vpcAllocation
}

func (c *PodContainer) VPCAccountID() *string {
	return c.podConfig.AccountID
}

func getContainerResources(userContainer *corev1.Container) (*Resources, error) {
	gpus := int64(0)
	if numGPUs, ok := userContainer.Resources.Limits[resourceCommon.ResourceNameGpu]; ok {
		gpus = numGPUs.Value()
	}
	net, ok := userContainer.Resources.Limits[resourceCommon.ResourceNameNetwork]
	if !ok {
		return nil, fmt.Errorf("pod did not contain network resource limit: %s", resourceCommon.ResourceNameNetwork)
	}

	// XXX: what about when bytes are used?
	return &Resources{
		CPU:     userContainer.Resources.Limits.Cpu().Value(),
		Disk:    userContainer.Resources.Limits.StorageEphemeral().Value() / units.MiB,
		GPU:     gpus,
		Mem:     userContainer.Resources.Limits.Memory().Value() / units.MiB,
		Network: net.Value() / units.MB,
	}, nil
}

func createLogUploadConfig(pConf *podCommon.Config) *uploader.Config {
	conf := uploader.Config{}
	if pConf.LogS3WriterIAMRole != nil {
		conf.S3WriterRole = *pConf.LogS3WriterIAMRole
	}
	if pConf.LogS3BucketName != nil {
		conf.S3BucketName = *pConf.LogS3BucketName
	}
	if pConf.LogS3PathPrefix != nil {
		conf.S3PathPrefix = *pConf.LogS3PathPrefix
	}

	return &conf
}
