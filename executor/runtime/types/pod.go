package types

import (
	"encoding/base64"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
	"github.com/Netflix/titus-executor/uploader"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	resourceCommon "github.com/Netflix/titus-kube-common/resource"
	"github.com/docker/distribution/reference"
	units "github.com/docker/go-units"
	"github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/maps"
	ptr "k8s.io/utils/pointer"
)

const (
	serviceMeshServiceName    = "servicemesh"
	serviceMeshServiceVersion = 1
	ShmMountPath              = "/dev/shm"
)

// Compile-time check that PodContainer implements the Container interface:
var _ Container = (*PodContainer)(nil)

// PodContainer is an implementation of Container backed only by a kubernetes pod.
// This is currently using the base64'ed ContainerInfo until all fields are ported over to annotations
type PodContainer struct {
	capabilities   *corev1.Capabilities
	config         config.Config
	containerImage reference.Reference
	ebsInfo        EBSInfo
	entrypoint     []string
	command        []string
	envLock        sync.Mutex
	// envOverrides are set by the executor for things like IPv4 / IPv6 address
	envOverrides map[string]string
	// ID is the container ID (in Docker). It is set by the container runtime after starting up.
	id    string
	image string
	// Is this container meant to run SystemD?
	isSystemD bool
	// GPU devices
	gpuInfo            GPUContainer
	labels             map[string]string
	logUploaderConfig  *uploader.Config
	nfsMounts          []NFSMount
	pod                *corev1.Pod
	podConfig          *podCommon.Config
	resources          *Resources
	serviceMeshEnabled bool
	serviceMeshImage   string
	shmSizeMiB         *uint32
	titusInfo          *titus.ContainerInfo
	ttyEnabled         bool
	// userEnv is the environment passed in by the user in the pod spec
	userEnv       map[string]string
	vpcAllocation *vpcapi.Assignment
}

func NewPodContainer(pod *corev1.Pod, cfg config.Config) (*PodContainer, error) {
	if pod == nil {
		return nil, errors.New("missing pod")
	}

	pConf, err := podCommon.PodToConfig(pod)
	if err != nil {
		return nil, err
	}

	userContainer := podCommon.GetUserContainer(pod)
	if userContainer == nil {
		return nil, errors.New("no containers found in pod")
	}

	resources, err := getContainerResources(userContainer)
	if err != nil {
		return nil, err
	}

	userEnv := map[string]string{}
	for _, envVar := range userContainer.Env {
		userEnv[envVar.Name] = envVar.Value
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
		ttyEnabled:        userContainer.TTY,
		userEnv:           userEnv,
	}

	// If the containerInfo annotation was set, use it
	if pConf.ContainerInfo != nil {
		cInfo, err := extractContainerInfo(pConf)
		if err != nil {
			return nil, err
		}
		c.titusInfo = cInfo
	} else {
		// No containerInfo: we need to know which env vars are user vs Titus so Metatron works
		if pConf.UserEnvVarsStartIndex == nil {
			return nil, fmt.Errorf("user environment variable index annotation is required: %s", podCommon.AnnotationKeyPodTitusUserEnvVarsStartIndex)
		}
	}

	err = c.parsePodVolumes()
	if err != nil {
		return c, fmt.Errorf("error parsing mounts: %w", err)
	}
	err = c.parsePodEmptyDirVolumes()
	if err != nil {
		return c, fmt.Errorf("error parsing EmptyDir mounts: %w", err)
	}

	err = c.extractServiceMesh()
	if err != nil {
		return c, fmt.Errorf("error extracting service mesh image: %w", err)
	}

	if userContainer.SecurityContext != nil && userContainer.SecurityContext.Capabilities != nil {
		c.capabilities = userContainer.SecurityContext.Capabilities
	}

	err = c.parsePodCommandAndArgs()
	if err != nil {
		return c, fmt.Errorf("error parsing command and args for container \"%s\": %w", userContainer.Name, err)
	}

	// This requires entrypoint and command to be parsed first
	c.labels = addLabels(c.id, c, resources)

	return c, nil
}

func (c *PodContainer) AllowCPUBursting() bool {
	if c.podConfig.CPUBurstingEnabled != nil {
		return *c.podConfig.CPUBurstingEnabled
	}
	return false
}

func (c *PodContainer) AllowNetworkBursting() bool {
	if c.podConfig.NetworkBurstingEnabled != nil {
		return *c.podConfig.NetworkBurstingEnabled
	}
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
	v6Enabled := c.podConfig.AssignIPv6Address
	if v6Enabled != nil {
		return *v6Enabled
	}
	return false
}

func (c *PodContainer) BandwidthLimitMbps() *int64 {
	bw := c.podConfig.IngressBandwidth
	if bw == nil {
		return nil
	}

	return ptr.Int64Ptr(bw.Value())
}

func (c *PodContainer) BatchPriority() *string {
	if c.podConfig.SchedPolicy != nil {
		return c.podConfig.SchedPolicy
	}
	return nil
}

func (c *PodContainer) Capabilities() *corev1.Capabilities {
	return c.capabilities
}

func (c *PodContainer) CombinedAppStackDetails() string {
	return combinedAppStackDetails(c)
}

func (c *PodContainer) ContainerInfo() (*titus.ContainerInfo, error) {
	// TODO: this needs to be removed once Metatron supports pods

	if c.titusInfo != nil {
		// ContainerInfo was passed in the attribute: return it
		return c.titusInfo, nil
	}

	userContainer := podCommon.GetUserContainer(c.pod)
	appName := c.AppName()
	stack := c.JobGroupStack()
	detail := c.JobGroupDetail()
	seq := c.JobGroupSequence()
	sgIDs := []string{}
	titusProvidedEnv := map[string]string{}
	userProvidedEnv := map[string]string{}

	if c.SecurityGroupIDs() != nil {
		sgIDs = *c.SecurityGroupIDs()
	}

	userEnvStartIdx := *c.podConfig.UserEnvVarsStartIndex
	for i, env := range userContainer.Env {
		if uint32(i) < userEnvStartIdx {
			titusProvidedEnv[env.Name] = env.Value
		} else {
			userProvidedEnv[env.Name] = env.Value
		}
	}

	// Only populate ContainerInfo with the fields necessary for a valid task identity document
	cInfo := &titus.ContainerInfo{
		ImageName: c.ImageName(),
		// Command
		Version: c.ImageVersion(),
		JobId:   c.JobID(),
		// EntrypointStr
		AppName:        &appName,
		JobGroupStack:  &stack,
		JobGroupDetail: &detail,
		IamProfile:     c.IamRole(),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			// This isn't used, but is marked as required in the protobuf
			EniLablel:      ptr.StringPtr("0"),
			SecurityGroups: sgIDs,
		},
		JobGroupSequence: &seq,
		MetatronCreds: &titus.ContainerInfo_MetatronCreds{
			AppMetadata: c.podConfig.AppMetadata,
			MetadataSig: c.podConfig.AppMetadataSig,
		},
		UserProvidedEnv:  userProvidedEnv,
		TitusProvidedEnv: titusProvidedEnv,
		ImageDigest:      c.ImageDigest(),
		// Use the entrypoint and command originally passed to us, not ones in `c`,
		// since those could have shell splitting performed on them
		Process: &titus.ContainerInfo_Process{
			Entrypoint: userContainer.Command,
			Command:    userContainer.Args,
		},
		JobAcceptedTimestampMs: c.podConfig.JobAcceptedTimestampMs,
	}

	return cInfo, nil
}

func (c *PodContainer) EBSInfo() EBSInfo {
	return c.ebsInfo
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
	if c.podConfig.ElasticIPPool != nil {
		return c.podConfig.ElasticIPPool
	}
	return nil
}

func (c *PodContainer) ElasticIPs() *string {
	if c.podConfig.ElasticIPs != nil {
		return c.podConfig.ElasticIPs
	}
	return nil
}

func (c *PodContainer) FuseEnabled() bool {
	if c.podConfig.FuseEnabled != nil {
		return *c.podConfig.FuseEnabled
	}
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
	imageName := ""
	if img := c.ImageName(); img != nil {
		imageName = *img
	}

	return map[string]string{"image": imageName}
}

func (c *PodContainer) IPv4Address() *string {
	if c.vpcAllocation == nil {
		return nil
	}
	switch t := c.vpcAllocation.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
		if t.AssignIPResponseV3.Ipv4Address != nil {
			return &t.AssignIPResponseV3.Ipv4Address.Address.Address
		}
	}
	panic("Unxpected state")
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
	waitSec := c.pod.Spec.TerminationGracePeriodSeconds
	if waitSec != nil && *waitSec != 0 {
		intWaitSec := uint32(*waitSec)
		return &intWaitSec
	}

	return nil
}

func (c *PodContainer) KvmEnabled() bool {
	if c.podConfig.KvmEnabled != nil {
		return *c.podConfig.KvmEnabled
	}
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
	if c.podConfig.AppMetadata == nil || c.podConfig.AppMetadataSig == nil {
		return nil
	}

	return &titus.ContainerInfo_MetatronCreds{
		AppMetadata: c.podConfig.AppMetadata,
		MetadataSig: c.podConfig.AppMetadataSig,
	}
}

func (c *PodContainer) NFSMounts() []NFSMount {
	return c.nfsMounts
}

func (c *PodContainer) NormalizedENIIndex() *int {
	// This is unused in the v3 vpc service
	unused := int(0)
	return &unused
}

func (c *PodContainer) OomScoreAdj() *int32 {
	return c.podConfig.OomScoreAdj
}

func (c *PodContainer) OwnerEmail() *string {
	return c.podConfig.AppOwnerEmail
}

func (c *PodContainer) Process() ([]string, []string) {
	return c.entrypoint, c.command
}

func (c *PodContainer) QualifiedImageName() string {
	return c.image
}

func (c *PodContainer) Resources() *Resources {
	return c.resources
}

func (c *PodContainer) RequireIMDSToken() *string {
	return c.podConfig.IMDSRequireToken
}

func (c *PodContainer) Runtime() string {
	if c.gpuInfo != nil {
		return c.gpuInfo.Runtime()
	}
	return DefaultOciRuntime
}

func (c *PodContainer) SeccompAgentEnabledForNetSyscalls() bool {
	if c.podConfig.SeccompAgentNetEnabled != nil {
		return *c.podConfig.SeccompAgentNetEnabled
	}
	return false
}

func (c *PodContainer) SeccompAgentEnabledForPerfSyscalls() bool {
	if c.podConfig.SeccompAgentPerfEnabled != nil {
		return *c.podConfig.SeccompAgentPerfEnabled
	}
	return false
}

func (c *PodContainer) SecurityGroupIDs() *[]string {
	return c.podConfig.SecurityGroupIDs
}

func (c *PodContainer) ServiceMeshEnabled() bool {
	return c.serviceMeshEnabled
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

func (c *PodContainer) SetVPCAllocation(allocation *vpcapi.Assignment) {
	c.vpcAllocation = allocation
}

func (c *PodContainer) ShmSizeMiB() *uint32 {
	return c.shmSizeMiB
}

func (c *PodContainer) SidecarConfigs() ([]*ServiceOpts, error) {
	svcMeshImage := ""
	if c.ServiceMeshEnabled() {
		svcMeshImage = c.serviceMeshImage
	}

	imageMap := map[string]string{
		SidecarServiceAbMetrix:    c.config.AbmetrixServiceImage,
		SidecarServiceLogViewer:   c.config.LogViewerServiceImage,
		SidecarServiceMetatron:    c.config.MetatronServiceImage,
		SidecarServiceServiceMesh: svcMeshImage,
		SidecarServiceSshd:        c.config.SSHDServiceImage,
		SidecarServiceSpectatord:  c.config.SpectatordServiceImage,
		SidecarServiceAtlasd:      c.config.AtlasdServiceImage,
		SidecarContainerTools:     c.config.ContainerToolsImage,
	}

	sideCarPtrs := []*ServiceOpts{}
	for _, scOrig := range sideCars {
		// Make a copy to avoid mutating the original
		sc := scOrig
		imgName := imageMap[sc.ServiceName]
		if imgName != "" {
			sc.Image = path.Join(c.config.DockerRegistry, imgName)
		}
		sideCarPtrs = append(sideCarPtrs, &sc)
	}

	return sideCarPtrs, nil
}

func (c *PodContainer) SignedAddressAllocationUUID() *string {
	return c.podConfig.StaticIPAllocationUUID
}

func (c *PodContainer) SortedEnvArray() []string {
	return sortedEnv(c.Env())
}

func (c *PodContainer) SubnetIDs() *[]string {
	return c.podConfig.SubnetIDs
}

func (c *PodContainer) TaskID() string {
	return c.pod.Name
}

func (c *PodContainer) TTYEnabled() bool {
	return c.ttyEnabled
}

func (c *PodContainer) UploadDir(namespace string) string {
	return filepath.Join("titan", c.config.Stack, namespace, c.TaskID())
}

func (c *PodContainer) UseJumboFrames() bool {
	if c.podConfig.JumboFramesEnabled != nil {
		return *c.podConfig.JumboFramesEnabled
	}
	return false
}

func (c *PodContainer) VPCAllocation() *vpcapi.Assignment {
	return c.vpcAllocation
}

func (c *PodContainer) VPCAccountID() *string {
	if c.podConfig.AccountID != nil {
		return c.podConfig.AccountID
	}
	return &c.config.SSHAccountID
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
	pod.Annotations[podCommon.AnnotationKeyPodTitusContainerInfo] = b64str
	return nil
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

func (c *PodContainer) parsePodVolumes() error {
	c.nfsMounts = []NFSMount{}
	nameToMount := map[string]corev1.Volume{}
	c.ebsInfo = EBSInfo{}

	for _, vol := range c.pod.Spec.Volumes {
		if vol.VolumeSource.NFS == nil && vol.VolumeSource.AWSElasticBlockStore == nil {
			continue
		}
		nameToMount[vol.Name] = vol
	}

	uc := podCommon.GetUserContainer(c.pod)
	for _, vm := range uc.VolumeMounts {
		vol, ok := nameToMount[vm.Name]
		if !ok {
			continue
		}

		if vol.VolumeSource.NFS != nil {
			c.nfsMounts = append(c.nfsMounts, NFSMount{
				MountPoint: filepath.Clean(vm.MountPath),
				Server:     vol.NFS.Server,
				ServerPath: filepath.Clean(vol.NFS.Path),
				ReadOnly:   vol.NFS.ReadOnly,
			})
		}

		if vol.VolumeSource.AWSElasticBlockStore != nil {
			if c.ebsInfo.VolumeID != "" {
				return errors.New("only one EBS volume per task can be specified")
			}
			c.ebsInfo = EBSInfo{
				VolumeID:  vol.AWSElasticBlockStore.VolumeID,
				FSType:    vol.AWSElasticBlockStore.FSType,
				MountPath: vm.MountPath,
				MountPerm: "RW",
			}
			if vol.VolumeSource.AWSElasticBlockStore.ReadOnly {
				c.ebsInfo.MountPerm = "RO"
			}
		}

		delete(nameToMount, vm.Name)
	}

	return nil
}

func (c *PodContainer) parsePodEmptyDirVolumes() error {
	var shmVM *corev1.VolumeMount
	uc := podCommon.GetUserContainer(c.pod)

	for i := range uc.VolumeMounts {
		vm := uc.VolumeMounts[i]
		if vm.MountPath == ShmMountPath {
			shmVM = &vm
			break
		}
	}

	if shmVM == nil {
		return nil
	}

	for _, vol := range c.pod.Spec.Volumes {
		if vol.VolumeSource.EmptyDir == nil {
			continue
		}
		if vol.Name != shmVM.Name {
			continue
		}

		if vol.VolumeSource.EmptyDir.SizeLimit == nil {
			continue
		}

		intVal, ok := vol.VolumeSource.EmptyDir.SizeLimit.AsInt64()
		if !ok {
			return fmt.Errorf("error parsing resource value of volume: %s", vol.Name)
		}

		uintVal := uint32(intVal / units.MiB)
		c.shmSizeMiB = &uintVal
	}

	if shmVM != nil && c.shmSizeMiB == nil {
		return fmt.Errorf("container volume mount found with unmatched pod volume: %s", shmVM.Name)
	}

	return nil
}

func (c *PodContainer) extractServiceMesh() error {
	var scConf *podCommon.Sidecar

	for i := range c.podConfig.Sidecars {
		sc := &c.podConfig.Sidecars[i]
		if sc.Name == serviceMeshServiceName && sc.Version == serviceMeshServiceVersion {
			scConf = sc
			break
		}
	}

	// If service mesh image has been explicitly disabled by an annotation, go no further
	if scConf != nil {
		if !scConf.Enabled {
			return nil
		}
		c.serviceMeshEnabled = scConf.Enabled

		// If service mesh image has been specified in by an annotation, use that
		if scConf.Image != "" {
			c.serviceMeshImage = scConf.Image
			return nil
		}
	}

	if !c.config.ContainerServiceMeshEnabled {
		return nil
	}

	if c.config.ProxydServiceImage == "" {
		return nil
	}

	c.serviceMeshImage = c.config.ProxydServiceImage
	c.serviceMeshEnabled = true

	return nil
}

// Optionally do shell splitting on the container's Command if the appropriate annotation is set. We do this
// because lots of jobs still depend on this behaviour. Unfortunately, this parsing can't be done in
// the TJC and passed down to the executor, because Titus clients sign jobs with the original unparsed Command
// and Args. If the executor reports something different than what was in the signature, this breaks Metatron.
func (c *PodContainer) parsePodCommandAndArgs() error {
	uc := podCommon.GetUserContainer(c.pod)
	c.entrypoint = uc.Command
	c.command = uc.Args

	if c.podConfig.EntrypointShellSplitting == nil || !*c.podConfig.EntrypointShellSplitting {
		return nil
	}

	if len(c.entrypoint) == 0 && len(c.command) == 0 {
		return nil
	}

	if len(c.command) > 0 {
		return nil
	}

	parsedEntryPoint, err := dockershellparser.ProcessWords(strings.Join(c.entrypoint, " "), []string{})
	if err != nil {
		return err
	}

	c.entrypoint = parsedEntryPoint
	c.command = nil

	return nil
}

func extractContainerInfo(pConf *podCommon.Config) (*titus.ContainerInfo, error) {
	cInfoStr := pConf.ContainerInfo
	if cInfoStr == nil {
		return nil, fmt.Errorf("unable to find containerInfo annotation: %s", podCommon.AnnotationKeyPodTitusContainerInfo)
	}

	data, err := base64.StdEncoding.DecodeString(*cInfoStr)
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
