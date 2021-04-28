package types

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	"github.com/apex/log"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/maps"
	ptr "k8s.io/utils/pointer"
)

const (
	appNameLabelKey          = "com.netflix.titus.appName"
	commandLabelKey          = "com.netflix.titus.command"
	entrypointLabelKey       = "com.netflix.titus.entrypoint"
	cpuLabelKey              = "com.netflix.titus.cpu"
	iamRoleLabelKey          = "ec2.iam.role"
	memLabelKey              = "com.netflix.titus.mem"
	diskLabelKey             = "com.netflix.titus.disk"
	networkLabelKey          = "com.netflix.titus.network"
	workloadTypeLabelKey     = "com.netflix.titus.workload.type"
	ownerEmailLabelKey       = "com.netflix.titus.owner.email"
	ownerEmailPassThroughKey = "titus.agent.ownerEmail"
	jobTypeLabelKey          = "com.netflix.titus.job.type"
	jobTypePassThroughKey    = "titus.agent.jobType"
	TitusTaskInstanceIDKey   = "TITUS_TASK_INSTANCE_ID"
	titusJobIDKey            = "TITUS_JOB_ID"

	// Passthrough params
	s3WriterRoleParam                       = "titusParameter.agent.log.s3WriterRole"
	s3BucketNameParam                       = "titusParameter.agent.log.s3BucketName"
	s3PathPrefixParam                       = "titusParameter.agent.log.s3PathPrefix"
	hostnameStyleParam                      = "titusParameter.agent.hostnameStyle"
	logUploadThresholdTimeParam             = "titusParameter.agent.log.uploadThresholdTime"
	logUploadCheckIntervalParam             = "titusParameter.agent.log.uploadCheckInterval"
	logStdioCheckIntervalParam              = "titusParameter.agent.log.stdioCheckInterval"
	LogKeepLocalFileAfterUploadParam        = "titusParameter.agent.log.keepLocalFileAfterUpload"
	FuseEnabledParam                        = "titusParameter.agent.fuseEnabled"
	KvmEnabledParam                         = "titusParameter.agent.kvmEnabled"
	SeccompAgentEnabledForNetSyscallsParam  = "titusParameter.agent.seccompAgentEnabledForNetSyscalls"
	SeccompAgentEnabledForPerfSyscallsParam = "titusParameter.agent.seccompAgentEnabledForPerfSyscalls"
	assignIPv6AddressParam                  = "titusParameter.agent.assignIPv6Address"
	batchPriorityParam                      = "titusParameter.agent.batchPriority"
	serviceMeshEnabledParam                 = "titusParameter.agent.service.serviceMesh.enabled"
	serviceMeshContainerParam               = "titusParameter.agent.service.serviceMesh.container"
	ttyEnabledParam                         = "titusParameter.agent.ttyEnabled"
	jumboFrameParam                         = "titusParameter.agent.allowNetworkJumbo"
	AccountIDParam                          = "titusParameter.agent.accountId"
	imdsRequireTokenParam                   = "titusParameter.agent.imds.requireToken"
	subnetsParam                            = "titusParameter.agent.subnets"
	elasticIPPoolParam                      = "titusParameter.agent.elasticIPPool"
	elasticIPsParam                         = "titusParameter.agent.elasticIPs"

	// DefaultOciRuntime is the default oci-compliant runtime used to run system services
	DefaultOciRuntime = "runc"
)

var (
	// log uploading defaults
	defaultLogUploadThresholdTime = 6 * time.Hour
	defaultLogUploadCheckInterval = 15 * time.Minute
	defaultStdioLogCheckInterval  = 1 * time.Minute
)

// WorkloadType classifies isolation behaviors on resources (e.g. CPU).  The exact implementation details of the
// isolation mechanism are determine by an isolation service (e.g. titus-isolate).
type WorkloadType string

// Regardless of isolation mechanism:
//
//     "static" workloads are provided resources which to the greatest degree possible are isolated from other workloads
//     on a given host.  In return they opt out of the opportunity to consume unused resources opportunistically.
//
//     "burst" workloads opt in to consumption of unused resources on a host at the cost of accepting the possibility of
//     more resource interference from other workloads.
const (
	StaticWorkloadType WorkloadType = "static"
	BurstWorkloadType  WorkloadType = "burst"
)

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}

func strPtrOr(str string, defStr *string) *string {
	if str != "" {
		return &str
	}

	return defStr
}

// TitusInfoContainer is an implementation of Container backed partially
// by ContainerInfo, and partially by a k8s pod (for env variables).
//
// Note that all private fields are intended to be set in the constructor
// via passthrough attributes. All others are read from ContainerInfo.
type TitusInfoContainer struct {
	// ID is the container ID (in Docker). It is set by the container runtime after starting up.
	id      string
	taskID  string
	jobID   string
	envLock sync.Mutex
	// envOverrides are set by the executor for things like IPv4 / IPv6 address
	envOverrides map[string]string
	labels       map[string]string
	titusInfo    *titus.ContainerInfo

	resources Resources

	// VPC driver fields
	// assignIPv6Address is only here to capture the legacy passthrough parameter
	// TODO: Remove once all jobs are using NetworkMode
	assignIPv6Address  bool
	elasticIPPool      string
	elasticIPs         string
	normalizedENIIndex int
	subnetIDs          string
	useJumboFrames     bool
	vpcAllocation      *vpcapi.Assignment
	vpcAccountID       string

	// Log uploader fields
	logUploadThresholdTime *time.Duration
	logUploadCheckInterval *time.Duration
	logStdioCheckInterval  *time.Duration
	// LogLocalFileAfterUpload indicates whether or not we should delete log files after uploading them
	logKeepLocalFileAfterUpload bool
	logUploadRegexp             *regexp.Regexp
	logUploaderConfig           uploader.Config

	pod       *corev1.Pod
	podConfig *podCommon.Config

	// extraUserContainers stores and array of metadata about all the non-main user containers
	extraUserContainers []*ExtraContainer
	// extraUserContainers stores and array of metadata about all the platform-defined containers
	extraPlatformContainers []*ExtraContainer

	// GPU devices
	gpuInfo GPUContainer

	entrypoint []string
	command    []string

	batchPriority string
	hostnameStyle string
	// Is this container meant to run SystemD?
	isSystemD bool
	// FuseEnabled determines whether the container has FUSE devices exposed to it
	fuseEnabled bool
	// KvmEnabled determines whether the container has KVM exposed to it
	kvmEnabled                         bool
	nfsMounts                          []NFSMount
	requireIMDSToken                   string
	seccompAgentEnabledForNetSyscalls  bool
	seccompAgentEnabledForPerfSyscalls bool
	serviceMeshEnabled                 *bool
	serviceMeshImage                   string
	ttyEnabled                         bool

	config config.Config
}

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, resources Resources, cfg config.Config) (Container, error) {
	return NewContainerWithPod(taskID, titusInfo, resources, cfg, nil)
}

// NewContainerWithPod allocates and initializes a new container struct object. Pod can be optionally passed. If nil, ignored
func NewContainerWithPod(taskID string, titusInfo *titus.ContainerInfo, resources Resources, cfg config.Config, pod *corev1.Pod) (Container, error) {
	if pod != nil {
		schemaVer, err := podCommon.PodSchemaVersion(pod)
		if err != nil {
			return nil, err
		}

		if schemaVer > 0 {
			return NewPodContainer(pod, cfg)
		}
	}

	return NewTitusInfoContainer(taskID, titusInfo, resources, cfg, pod)
}

// NewTitusInfoContainer creates a new container backed by a pod with a ContainerInfo annotation
func NewTitusInfoContainer(taskID string, titusInfo *titus.ContainerInfo, resources Resources, cfg config.Config, pod *corev1.Pod) (*TitusInfoContainer, error) {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()

	c := &TitusInfoContainer{
		taskID:       taskID,
		titusInfo:    titusInfo,
		resources:    resources,
		envOverrides: map[string]string{},
		config:       cfg,
	}

	if pod != nil {
		c.pod = pod.DeepCopy()
	}

	if c.pod != nil {
		c.extraUserContainers, c.extraPlatformContainers = NewExtraContainersFromPod(*c.pod)
	}

	c.podConfig = &podCommon.Config{}
	if c.pod != nil {
		pConf, err := podCommon.PodToConfig(pod)
		if err != nil {
			return nil, err
		}
		c.podConfig = pConf
	}

	if eniLabel := networkCfgParams.GetEniLabel(); eniLabel != "" {
		titusENIIndex, err := strconv.Atoi(networkCfgParams.GetEniLabel())
		if err != nil {
			panic(err)
		}
		// Titus uses the same indexes as the EC2 device id
		// Titus Index 1 = ENI index 0
		c.normalizedENIIndex = titusENIIndex + 1
	}

	if err := validateIamRole(c.IamRole()); err != nil {
		return nil, err
	}

	if err := c.updateLogAttributes(titusInfo); err != nil {
		return nil, err
	}

	entrypoint, command, err := parseEntryPointAndCommand(titusInfo)
	if err != nil {
		return nil, err
	}
	if entrypoint != nil {
		c.entrypoint = entrypoint
	}
	if command != nil {
		c.command = command
	}

	stringPassthroughs := []struct {
		paramName     string
		containerAttr *string
	}{
		{
			paramName:     AccountIDParam,
			containerAttr: &c.vpcAccountID,
		},
		{
			paramName:     subnetsParam,
			containerAttr: &c.subnetIDs,
		},
		{
			paramName:     elasticIPPoolParam,
			containerAttr: &c.elasticIPPool,
		},
		{
			paramName:     elasticIPsParam,
			containerAttr: &c.elasticIPs,
		},
		{
			paramName:     serviceMeshContainerParam,
			containerAttr: &c.serviceMeshImage,
		},
		{
			paramName:     batchPriorityParam,
			containerAttr: &c.batchPriority,
		},
		{
			paramName:     imdsRequireTokenParam,
			containerAttr: &c.requireIMDSToken,
		},
		{
			paramName:     hostnameStyleParam,
			containerAttr: &c.hostnameStyle,
		},
	}

	for _, pt := range stringPassthroughs {
		if val, ok := titusInfo.GetPassthroughAttributes()[pt.paramName]; ok {
			*pt.containerAttr = val
		}
	}

	if err := validateHostnameStyle(c.hostnameStyle); err != nil {
		return nil, err
	}

	boolPassthroughs := []struct {
		paramName     string
		containerAttr *bool
	}{
		{
			paramName:     FuseEnabledParam,
			containerAttr: &c.fuseEnabled,
		},
		{
			paramName:     LogKeepLocalFileAfterUploadParam,
			containerAttr: &c.logKeepLocalFileAfterUpload,
		},
		{
			paramName:     KvmEnabledParam,
			containerAttr: &c.kvmEnabled,
		},
		{
			paramName:     SeccompAgentEnabledForNetSyscallsParam,
			containerAttr: &c.seccompAgentEnabledForNetSyscalls,
		},
		{
			paramName:     SeccompAgentEnabledForPerfSyscallsParam,
			containerAttr: &c.seccompAgentEnabledForPerfSyscalls,
		},
		{
			paramName:     ttyEnabledParam,
			containerAttr: &c.ttyEnabled,
		},
		{
			paramName:     assignIPv6AddressParam,
			containerAttr: &c.assignIPv6Address,
		},
		{
			paramName:     jumboFrameParam,
			containerAttr: &c.useJumboFrames,
		},
	}

	for _, pt := range boolPassthroughs {
		enabled, ok, err := getPassthroughBool(titusInfo, pt.paramName)
		if err != nil {
			return c, err
		}
		if ok {
			*pt.containerAttr = enabled
		}
	}

	// c.serviceMeshEnabled is a bool pointer so that we can distinguish between the
	// passthrough param deliberately setting it to false versus it being unset
	svcMeshEnabled, ok, err := getPassthroughBool(titusInfo, serviceMeshEnabledParam)
	if err != nil {
		return c, err
	}
	if ok {
		c.serviceMeshEnabled = &svcMeshEnabled
	}

	err = c.parseContainerInfoNfsMounts()
	if err != nil {
		return c, fmt.Errorf("error parsing NFS mounts: %w", err)
	}

	// This depends on a number of the other fields being populated, so run it last
	cEnv := c.Env()
	c.labels = addLabels(taskID, c, &resources)
	c.jobID = cEnv[titusJobIDKey]

	return c, nil
}

func addLabels(taskID string, c Container, resources *Resources) map[string]string {
	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      taskID,
		TitusTaskInstanceIDKey:  taskID,
	}

	iamRole := c.IamRole()
	if iamRole != nil {
		labels[iamRoleLabelKey] = *iamRole
	}

	labels[cpuLabelKey] = itoa(resources.CPU)
	labels[memLabelKey] = itoa(resources.Mem)
	labels[diskLabelKey] = itoa(resources.Disk)
	labels[networkLabelKey] = itoa(resources.Network)

	labels = addContainerLabels(c, labels)
	labels = addPassThroughLabels(c, labels)
	labels = addProcessLabels(c, labels)
	return labels
}

func addContainerLabels(c Container, labels map[string]string) map[string]string {
	labels[appNameLabelKey] = c.AppName()

	workloadType := StaticWorkloadType
	if c.AllowCPUBursting() {
		workloadType = BurstWorkloadType
	}

	labels[workloadTypeLabelKey] = string(workloadType)

	return labels
}

func addPassThroughLabels(c Container, labels map[string]string) map[string]string {
	ownerEmailStr := ""
	jobTypeStr := ""

	jobType := c.JobType()
	if jobType != nil {
		jobTypeStr = *jobType
	}
	email := c.OwnerEmail()
	if email != nil {
		ownerEmailStr = *email
	}

	labels[ownerEmailLabelKey] = ownerEmailStr
	labels[jobTypeLabelKey] = jobTypeStr

	return labels
}

func addProcessLabels(c Container, labels map[string]string) map[string]string {
	entryPoint, command := c.Process()
	if entryPoint != nil {
		entryPointStr := strings.Join(entryPoint[:], " ")
		labels[entrypointLabelKey] = entryPointStr
	}

	if command != nil {
		commandStr := strings.Join(command[:], " ")
		labels[commandLabelKey] = commandStr
	}

	return labels
}

func (c *TitusInfoContainer) updateLogAttributes(titusInfo *titus.ContainerInfo) error {
	logUploadCheckIntervalStr, ok := titusInfo.GetPassthroughAttributes()[logUploadCheckIntervalParam]
	if ok {
		dur, err := c.parseLogUploadCheckInterval(logUploadCheckIntervalStr)
		if err != nil {
			return err
		}
		c.logUploadCheckInterval = &dur
	}

	logStdioCheckIntervalStr, ok := titusInfo.GetPassthroughAttributes()[logStdioCheckIntervalParam]
	if ok {
		dur, err := c.parseLogStdioCheckInterval(logStdioCheckIntervalStr)
		if err != nil {
			return err
		}
		c.logStdioCheckInterval = &dur
	}

	logUploadThresholdTimeStr, ok := titusInfo.GetPassthroughAttributes()[logUploadThresholdTimeParam]
	if ok {
		dur, err := c.parseLogUploadThresholdTime(logUploadThresholdTimeStr)
		if err != nil {
			return err
		}
		c.logUploadThresholdTime = &dur
	}

	uploadRegexpStr := titusInfo.GetLogUploadRegexp()
	if uploadRegexpStr != "" {
		uploadRegexp, err := regexp.Compile(uploadRegexpStr)
		if err != nil {
			return err
		}
		c.logUploadRegexp = uploadRegexp
	}

	if param, ok := titusInfo.GetPassthroughAttributes()[s3WriterRoleParam]; ok {
		c.logUploaderConfig.S3WriterRole = param
	}

	if param, ok := titusInfo.GetPassthroughAttributes()[s3BucketNameParam]; ok {
		c.logUploaderConfig.S3BucketName = param
	}

	if param, ok := titusInfo.GetPassthroughAttributes()[s3PathPrefixParam]; ok {
		c.logUploaderConfig.S3PathPrefix = param
	}

	return nil
}

func validateIamRole(iamRole *string) error {
	if iamRole == nil || *iamRole == "" {
		return ErrMissingIAMRole
	}

	if _, err := arn.Parse(*iamRole); err != nil {
		return fmt.Errorf("Could not parse iam profile %q, due to %w", *iamRole, err)
	}

	return nil
}

func (c *TitusInfoContainer) AllowCPUBursting() bool {
	return c.titusInfo.GetAllowCpuBursting()
}

func (c *TitusInfoContainer) AllowNetworkBursting() bool {
	return c.titusInfo.GetAllowNetworkBursting()
}

func (c *TitusInfoContainer) AppArmorProfile() *string {
	if c.FuseEnabled() {
		return ptr.StringPtr("docker_fuse")
	}

	return nil
}

func (c *TitusInfoContainer) AppName() string {
	return c.titusInfo.GetAppName()
}

// AssignIPv6Address only stores if the AssignIPv6Address attribute is set, and does
// NOT represent the source of truth of whether a v6 address will be assigned.
func (c *TitusInfoContainer) AssignIPv6Address() bool {
	return c.assignIPv6Address
}

func (c *TitusInfoContainer) BandwidthLimitMbps() *int64 {
	return &c.resources.Network
}

// BatchPriority returns what the environment variable TITUS_BATCH should be set to.
// if it returns nil, TITUS_BATCH should be unset
func (c *TitusInfoContainer) BatchPriority() *string {
	idleStr := "idle"
	trueStr := True

	if c.resources.CPU == 0 {
		return &idleStr
	}

	if !c.titusInfo.GetBatch() {
		return nil
	}

	if c.batchPriority == "idle" {
		return &idleStr
	}

	return &trueStr
}

func (c *TitusInfoContainer) CombinedAppStackDetails() string {
	return combinedAppStackDetails(c)
}

// Config returns the container config with all necessary fields for validating its identity with Metatron
func (c *TitusInfoContainer) ContainerInfo() (*titus.ContainerInfo, error) {
	return c.titusInfo, nil
}

func (c *TitusInfoContainer) Capabilities() *corev1.Capabilities {
	cInfoCap := c.titusInfo.GetCapabilities()
	if cInfoCap == nil {
		return nil
	}

	cp := corev1.Capabilities{}
	for _, add := range cInfoCap.GetAdd() {
		cp.Add = append(cp.Add, corev1.Capability(add.String()))
	}
	for _, drop := range cInfoCap.GetDrop() {
		cp.Drop = append(cp.Drop, corev1.Capability(drop.String()))
	}

	return &cp
}

func (c *TitusInfoContainer) EBSInfo() EBSInfo {
	if c.pod == nil {
		return EBSInfo{}
	}
	if c.pod.Annotations == nil {
		return EBSInfo{}
	}
	return EBSInfo{
		VolumeID:  c.pod.Annotations[podCommon.AnnotationKeyStorageEBSVolumeID],
		MountPath: c.pod.Annotations[podCommon.AnnotationKeyStorageEBSMountPath],
		MountPerm: c.pod.Annotations[podCommon.AnnotationKeyStorageEBSMountPerm],
		FSType:    c.pod.Annotations[podCommon.AnnotationKeyStorageEBSFSType],
	}
}

func (c *TitusInfoContainer) ElasticIPPool() *string {
	return strPtrOr(c.elasticIPPool, nil)
}

func (c *TitusInfoContainer) ElasticIPs() *string {
	return strPtrOr(c.elasticIPs, nil)
}

func (c *TitusInfoContainer) Env() map[string]string {
	// passed environment
	passedEnv := func() map[string]string {
		containerInfoEnv := map[string]string{
			"TITUS_ENV_FROM": "containerInfo",
		}
		podEnv := map[string]string{
			"TITUS_ENV_FROM": "pod",
		}
		for key, value := range c.titusInfo.GetUserProvidedEnv() {
			if value != "" {
				containerInfoEnv[key] = value
				podEnv[key] = value
			}
		}
		for key, value := range c.titusInfo.GetTitusProvidedEnv() {
			containerInfoEnv[key] = value
			podEnv[key] = value
		}

		if c.pod == nil {
			return containerInfoEnv
		}
		// This is a "dumb" check -- that just makes sure at least 1 container exists so we don't null pointer exception
		// We probably don't want to blindly source env
		if len(c.pod.Spec.Containers) == 0 {
			return containerInfoEnv
		}
		if len(c.pod.Spec.Containers[0].Env) == 0 {
			return containerInfoEnv
		}

		for _, val := range c.pod.Spec.Containers[0].Env {
			podEnv[val.Name] = val.Value
		}
		if val, ok := podEnv[TitusTaskInstanceIDKey]; !ok {
			// We need to have the pod env have this variable
			return containerInfoEnv
		} else if val == "" {
			return containerInfoEnv
		}
		return podEnv
	}()

	return populateContainerEnv(c, c.config, passedEnv)
}

func (c *TitusInfoContainer) EnvOverrides() map[string]string {
	c.envLock.Lock()
	envOverrides := maps.CopySS(c.envOverrides)
	c.envLock.Unlock()
	return envOverrides
}

func (c *TitusInfoContainer) ExtraUserContainers() []*ExtraContainer {
	return c.extraUserContainers
}

func (c *TitusInfoContainer) ExtraPlatformContainers() []*ExtraContainer {
	return c.extraPlatformContainers
}

func (c *TitusInfoContainer) FuseEnabled() bool {
	return c.fuseEnabled
}

func (c *TitusInfoContainer) GPUInfo() GPUContainer {
	return c.gpuInfo
}

func (c *TitusInfoContainer) HostnameStyle() *string {
	return &c.hostnameStyle
}

func (c *TitusInfoContainer) IamRole() *string {
	return ptr.StringPtr(c.titusInfo.GetIamProfile())
}

func (c *TitusInfoContainer) ID() string {
	return c.id
}

func (c *TitusInfoContainer) ImageDigest() *string {
	digest := c.titusInfo.GetImageDigest()
	if digest != "" {
		return &digest
	}
	return nil
}

func (c *TitusInfoContainer) ImageName() *string {
	return strPtrOr(c.titusInfo.GetImageName(), nil)
}

func (c *TitusInfoContainer) ImageVersion() *string {
	return strPtrOr(c.titusInfo.GetVersion(), nil)
}

// ImageTagForMetrics returns a map with the image name
func (c *TitusInfoContainer) ImageTagForMetrics() map[string]string {
	imageName := ""
	if img := c.ImageName(); img != nil {
		imageName = *img
	}

	return map[string]string{"image": imageName}
}

func (c *TitusInfoContainer) IPv4Address() *string {
	if c.vpcAllocation == nil {
		return nil
	}
	addr := c.vpcAllocation.IPV4Address()
	if addr == nil {
		return nil
	}
	return &addr.Address.Address
}

func (c *TitusInfoContainer) IsSystemD() bool {
	return c.isSystemD
}

func (c *TitusInfoContainer) JobGroupDetail() string {
	return c.titusInfo.GetJobGroupDetail()
}

func (c *TitusInfoContainer) JobGroupStack() string {
	return c.titusInfo.GetJobGroupStack()
}

func (c *TitusInfoContainer) JobGroupSequence() string {
	return c.titusInfo.GetJobGroupSequence()
}

func (c *TitusInfoContainer) JobID() *string {
	return &c.jobID
}

func (c *TitusInfoContainer) JobType() *string {
	passthroughAttributes := c.titusInfo.GetPassthroughAttributes()
	if passthroughAttributes == nil {
		return nil
	}

	jobVal, ok := passthroughAttributes[jobTypePassThroughKey]
	if !ok {
		return nil
	}
	return &jobVal
}

func (c *TitusInfoContainer) KillWaitSeconds() *uint32 {
	val := c.titusInfo.GetKillWaitSeconds()
	if val != 0 {
		return &val
	}
	return nil
}

func (c *TitusInfoContainer) KvmEnabled() bool {
	return c.kvmEnabled
}

func (c *TitusInfoContainer) Labels() map[string]string {
	return c.labels
}

func (c *TitusInfoContainer) LogKeepLocalFileAfterUpload() bool {
	return c.logKeepLocalFileAfterUpload
}

// LogStdioCheckInterval indicates how often we should scan the stdio log files to determine whether they should be uploaded
func (c *TitusInfoContainer) LogStdioCheckInterval() *time.Duration {
	if c.logStdioCheckInterval != nil {
		return c.logStdioCheckInterval
	}

	return &defaultStdioLogCheckInterval
}

// LogUploadCheckInterval indicates how often we should scan the continers log directory to see if files need to be uploaded
func (c *TitusInfoContainer) LogUploadCheckInterval() *time.Duration {
	if c.logUploadCheckInterval != nil {
		return c.logUploadCheckInterval
	}

	return &defaultLogUploadCheckInterval
}

func (c *TitusInfoContainer) LogUploaderConfig() *uploader.Config {
	return &c.logUploaderConfig
}

func (c *TitusInfoContainer) LogUploadRegexp() *regexp.Regexp {
	return c.logUploadRegexp
}

// LogUploadThresholdTime indicates how long since a file was modified before we should upload it and delete it
func (c *TitusInfoContainer) LogUploadThresholdTime() *time.Duration {
	if c.logUploadThresholdTime != nil {
		return c.logUploadThresholdTime
	}

	return &defaultLogUploadThresholdTime
}

func (c *TitusInfoContainer) MetatronCreds() *titus.ContainerInfo_MetatronCreds {
	return c.titusInfo.GetMetatronCreds()
}

// EffectiveNetworkMode looks at the network mode set on the job (pod)
// If unset (very likely in these early days), we compute the "effective"
// network mode, based on attributes and other things.
// This allows us to still have nice things, like the NETWORK_MODE env variable
// be set correctly, even before NetworkMode is plumbed and set on all layers of the stack
// EffectiveNetworkMode can be removed some day when all clients of titus are setting
// it and no longer using the legacy attributes to imply network behavior.
func (c *TitusInfoContainer) EffectiveNetworkMode() string {
	mode := titus.NetworkConfiguration_UnknownNetworkMode.String()
	if c.podConfig != nil && c.podConfig.NetworkMode != nil {
		mode = *c.podConfig.NetworkMode
	}
	return computeEffectiveNetworkMode(mode, c.AssignIPv6Address(), c.SeccompAgentEnabledForNetSyscalls())
}

func (c *TitusInfoContainer) NFSMounts() []NFSMount {
	return c.nfsMounts
}

func (c *TitusInfoContainer) NormalizedENIIndex() *int {
	return &c.normalizedENIIndex
}

func (c *TitusInfoContainer) OomScoreAdj() *int32 {
	oomScore := c.titusInfo.GetOomScoreAdj()
	if oomScore != 0 {
		return &oomScore
	}

	return nil
}

func (c *TitusInfoContainer) OwnerEmail() *string {
	passthroughAttributes := c.titusInfo.GetPassthroughAttributes()
	if passthroughAttributes == nil {
		return nil
	}

	emailVal, ok := passthroughAttributes[ownerEmailPassThroughKey]
	if !ok {
		return nil
	}
	return &emailVal
}

// Process returns entrypoint and command for the container
func (c *TitusInfoContainer) Process() (entrypoint, cmd []string) {
	return c.entrypoint, c.command
}

// QualifiedImageName appends the registry and version to the Image name
func (c *TitusInfoContainer) QualifiedImageName() string {
	baseRef := c.titusInfo.GetFullyQualifiedImage()
	if baseRef == "" {
		baseRef = c.config.DockerRegistry + "/" + ptr.StringPtrDerefOr(c.ImageName(), "")
	}
	if c.ImageDigest() != nil {
		// digest has precedence
		withDigest := baseRef + "@" + ptr.StringPtrDerefOr(c.ImageDigest(), "")
		return withDigest
	}
	withVersion := baseRef + ":" + ptr.StringPtrDerefOr(c.ImageVersion(), "")
	return withVersion
}

func (c *TitusInfoContainer) Resources() *Resources {
	return &c.resources
}

func (c *TitusInfoContainer) RequireIMDSToken() *string {
	return &c.requireIMDSToken
}

func (c *TitusInfoContainer) Runtime() string {
	if c.gpuInfo != nil {
		return c.gpuInfo.Runtime()
	}
	return DefaultOciRuntime
}

func (c *TitusInfoContainer) SeccompAgentEnabledForPerfSyscalls() bool {
	return c.seccompAgentEnabledForPerfSyscalls
}

func (c *TitusInfoContainer) SeccompAgentEnabledForNetSyscalls() bool {
	return c.seccompAgentEnabledForNetSyscalls
}

func (c *TitusInfoContainer) SecurityGroupIDs() *[]string {
	networkCfgParams := c.titusInfo.GetNetworkConfigInfo()
	secGroups := networkCfgParams.GetSecurityGroups()
	return &secGroups
}

func (c *TitusInfoContainer) ServiceMeshEnabled() bool {
	enabled := c.config.ContainerServiceMeshEnabled
	if c.serviceMeshEnabled != nil {
		enabled = *c.serviceMeshEnabled
	}

	if !enabled {
		return false
	}
	_, err := c.serviceMeshImageName()
	return err == nil
}

func (c *TitusInfoContainer) serviceMeshImageName() (string, error) {
	container := c.serviceMeshImage
	if container == "" {
		container = c.config.ProxydServiceImage
	}

	if container == "" {
		return "no-container", errors.New("Could not determine proxyd image")
	}

	return container, nil
}

func (c *TitusInfoContainer) SetEnv(key, value string) {
	c.envLock.Lock()
	defer c.envLock.Unlock()
	c.envOverrides[key] = value
}

func (c *TitusInfoContainer) SetEnvs(env map[string]string) {
	c.envLock.Lock()
	defer c.envLock.Unlock()
	for key, value := range env {
		c.envOverrides[key] = value
	}
}

func (c *TitusInfoContainer) SetGPUInfo(gpuInfo GPUContainer) {
	c.gpuInfo = gpuInfo
}

// SetID sets the container ID for this container, updating internal data structures as necessary
func (c *TitusInfoContainer) SetID(id string) {
	c.id = id
	c.SetEnv(titusContainerIDEnvVariableName, id)
}

func (c *TitusInfoContainer) SetSystemD(isSystemD bool) {
	c.isSystemD = isSystemD
}

func (c *TitusInfoContainer) SetVPCAllocation(allocation *vpcapi.Assignment) {
	switch allocation.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
	default:
		panic(fmt.Errorf("Invalid assignment %v", allocation))
	}
	c.vpcAllocation = allocation
}

// ShmSizeMiB determines the container's /dev/shm size
func (c *TitusInfoContainer) ShmSizeMiB() *uint32 {
	shmSize := c.titusInfo.GetShmSizeMB()
	if shmSize != 0 {
		return &shmSize
	}
	return nil
}

func (c *TitusInfoContainer) SidecarConfigs() ([]*ServiceOpts, error) {
	svcMeshImage := ""
	sideCarPtrs := []*ServiceOpts{}
	if c.ServiceMeshEnabled() {
		img, err := c.serviceMeshImageName()
		if err != nil {
			return sideCarPtrs, err
		}
		svcMeshImage = img
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

	for _, scOrig := range sideCars {
		// Make a copy to avoid mutating the original
		sc := scOrig
		image, ok := imageMap[sc.ServiceName]
		if ok {
			sc.Image = path.Join(c.config.DockerRegistry, image)
			log.Debugf("computed sidecar image for %s image=%s", sc.ServiceName, sc.Image)
		}
		sideCarPtrs = append(sideCarPtrs, &sc)
	}

	return sideCarPtrs, nil
}

func (c *TitusInfoContainer) SignedAddressAllocationUUID() *string {
	if c.titusInfo.SignedAddressAllocation != nil {
		return &c.titusInfo.SignedAddressAllocation.AddressAllocation.Uuid
	}

	return nil
}

// GetSortedEnvArray returns the list of environment variables set for the container as a sorted Key=Value list
func (c *TitusInfoContainer) SortedEnvArray() []string {
	return sortedEnv(c.Env())
}

func (c *TitusInfoContainer) SubnetIDs() *[]string {
	if c.subnetIDs == "" {
		return nil
	}
	subnetIDs := strings.Split(c.subnetIDs, ",")
	for idx, subnetID := range subnetIDs {
		subnetIDs[idx] = strings.TrimSpace(subnetID)
	}
	return &subnetIDs
}

func (c *TitusInfoContainer) TaskID() string {
	return c.taskID
}

func (c *TitusInfoContainer) TTYEnabled() bool {
	return c.ttyEnabled
}

// UploadDir hold files that will by uploaded by log uploaders
func (c *TitusInfoContainer) UploadDir(namespace string) string {
	return filepath.Join("titan", c.config.Stack, namespace, c.TaskID())
}

func (c *TitusInfoContainer) UseJumboFrames() bool {
	return c.useJumboFrames
}

func (c *TitusInfoContainer) VPCAccountID() *string {
	return strPtrOr(c.vpcAccountID, &c.config.SSHAccountID)
}

func (c *TitusInfoContainer) VPCAllocation() *vpcapi.Assignment {
	return c.vpcAllocation
}

// Get a boolean passthrough attribute and whether it was present
func getPassthroughBool(titusInfo *titus.ContainerInfo, key string) (bool, bool, error) {
	value, ok := titusInfo.GetPassthroughAttributes()[key]

	if !ok {
		return false, false, nil
	}
	val, err := strconv.ParseBool(value)
	if err != nil {
		return false, true, err
	}

	return val, true, nil
}

// parseEntryPointAndCommand extracts Entrypoint and Cmd from TitusInfo expecting that only one of the below will be present:
//
// - TitusInfo.EntrypointStr, the old code path being deprecated. The flat string will be parsed according to shell
//   rules and be returned as entrypoint, while cmd will be nil
// - TitusInfo.Process, the new code path where both entrypoint and cmd are lists. Docker rules on how they interact
//   apply
//
// If both are set, EntrypointStr has precedence to allow for smoother transition.
func parseEntryPointAndCommand(titusInfo *titus.ContainerInfo) ([]string, []string, error) {
	if titusInfo.EntrypointStr != nil { // nolint: staticcheck
		// deprecated (old) way of passing entrypoints as a flat string. We need to parse it
		entrypoint, err := dockershellparser.ProcessWords(titusInfo.GetEntrypointStr(), []string{}) // nolint: megacheck
		if err != nil {
			return nil, nil, err
		}

		// nil cmd because everything is in the entrypoint
		return entrypoint, nil, nil
	}

	process := titusInfo.GetProcess()
	command := process.GetCommand()
	entrypoint := process.GetEntrypoint()
	return entrypoint, command, nil
}

func (c *TitusInfoContainer) parseLogUploadThresholdTime(logUploadThresholdTimeStr string) (time.Duration, error) {
	duration, err := time.ParseDuration(logUploadThresholdTimeStr)
	if err != nil {
		return 0, errors.Wrap(err, "Cannot parse log upload threshold time")
	}

	logUploadCheckInterval := c.LogUploadCheckInterval()
	logStdioCheckInterval := c.LogStdioCheckInterval()

	// Must be at least 2 * logUploadCheckInterval
	if duration <= *logUploadCheckInterval*2 {
		return 0, fmt.Errorf("Log upload threshold time %s must be at least 2 * %s, the log upload check interval", duration, logUploadCheckInterval)
	}

	if duration <= *logStdioCheckInterval*2 {
		return 0, fmt.Errorf("Log upload threshold time %s must be at least 2 * %s, the stdio check interval", duration, logUploadCheckInterval)
	}

	return duration, nil
}

func (c *TitusInfoContainer) parseLogUploadCheckInterval(logUploadCheckIntervalStr string) (time.Duration, error) {
	duration, err := time.ParseDuration(logUploadCheckIntervalStr)
	if err != nil {
		return 0, errors.Wrap(err, "Cannot parse log upload check interval")
	}
	if duration < time.Minute {
		return 0, fmt.Errorf("Log upload check interval '%s' must be at least 1 minute", duration)
	}
	return duration, nil
}

func (c *TitusInfoContainer) parseLogStdioCheckInterval(logStdioCheckIntervalStr string) (time.Duration, error) {
	duration, err := time.ParseDuration(logStdioCheckIntervalStr)
	if err != nil {
		return 0, errors.Wrap(err, "Cannot parse log stdio check interval")
	}
	return duration, nil
}

func populateContainerEnv(c Container, config config.Config, userEnv map[string]string) map[string]string {
	// Order goes (least priority, to highest priority:
	// -Hard coded environment variables
	// -Copied environment variables from the host
	// -Resource env variables
	// -User provided environment in POD (if pod unset, then fall back to containerinfo)
	// -Network Config
	// -Executor overrides

	// Hard coded (in executor config)
	env := config.GetHardcodedEnv()

	// Env copied from host
	for key, value := range config.GetEnvFromHost() {
		env[key] = value
	}

	// This variable comes early from the host, and later is overwritten
	// by other env variables injected from the control plane.
	// We save it here because it is useful to "leak" the true
	// instance ID we are running on for other infrastructure tools
	env["TITUS_HOST_EC2_INSTANCE_ID"] = env["EC2_INSTANCE_ID"]

	resources := c.Resources()
	// Resource environment variables
	env["TITUS_NUM_MEM"] = itoa(resources.Mem)
	env["TITUS_NUM_CPU"] = itoa(resources.CPU)
	env["TITUS_NUM_GPU"] = itoa(resources.GPU)
	env["TITUS_NUM_DISK"] = itoa(resources.Disk)
	env["TITUS_NUM_NETWORK_BANDWIDTH"] = itoa(resources.Network)

	cluster := c.CombinedAppStackDetails()
	env["NETFLIX_CLUSTER"] = cluster
	env["NETFLIX_STACK"] = c.JobGroupStack()
	env["NETFLIX_DETAIL"] = c.JobGroupDetail()

	var asgName string
	if seq := c.JobGroupSequence(); seq == "" {
		asgName = cluster + "-v000"
	} else {
		asgName = cluster + "-" + seq
	}
	env["NETFLIX_AUTO_SCALE_GROUP"] = asgName
	env["NETFLIX_APP"] = c.AppName()

	for key, value := range userEnv {
		env[key] = value
	}

	// These environment variables may be looked at things like sidecars and they should override user environment
	if name := c.ImageName(); name != nil {
		env["TITUS_IMAGE_NAME"] = *name
	}
	if tag := c.ImageVersion(); tag != nil {
		env["TITUS_IMAGE_TAG"] = *tag
	}
	if digest := c.ImageDigest(); digest != nil {
		env["TITUS_IMAGE_DIGEST"] = *digest
	}

	// The control plane should set this environment variable.
	// If it doesn't, we should set it. It shouldn't create
	// any problems if it is set to an "incorrect" value
	if _, ok := env["EC2_OWNER_ID"]; !ok {
		env["EC2_OWNER_ID"] = ptr.StringPtrDerefOr(c.VPCAccountID(), "")
	}

	env["TITUS_IAM_ROLE"] = ptr.StringPtrDerefOr(c.IamRole(), "")

	if config.MetatronEnabled {
		// When set, the metadata service will return signed identity documents suitable for bootstrapping Metatron
		env[metadataserverTypes.TitusMetatronVariableName] = True
	} else {
		env[metadataserverTypes.TitusMetatronVariableName] = False
	}

	netMode := GetHumanFriendlyNetworkMode(c.EffectiveNetworkMode())
	if netMode != "" {
		env["NETFLIX_NETWORK_MODE"] = netMode
	}
	vpcAllocation := c.VPCAllocation()
	if a := vpcAllocation.IPV4Address(); a != nil {
		env[metadataserverTypes.EC2IPv4EnvVarName] = a.Address.Address
	}

	if a := vpcAllocation.IPV6Address(); a != nil {
		env[metadataserverTypes.EC2IPv6sEnvVarName] = a.Address.Address
		env[metadataserverTypes.NetflixIPv6EnvVarName] = a.Address.Address
		env[metadataserverTypes.NetflixIPv6sEnvVarName] = a.Address.Address
	}

	if a := vpcAllocation.ElasticAddress(); a != nil {
		env[metadataserverTypes.EC2PublicIPv4EnvVarName] = a.Ip
		env[metadataserverTypes.EC2PublicIPv4sEnvVarName] = a.Ip
	}

	if a := vpcAllocation.ContainerENI(); a != nil {
		env["EC2_VPC_ID"] = a.VpcId
		env["EC2_INTERFACE_ID"] = a.NetworkInterfaceId
		env["EC2_SUBNET_ID"] = a.SubnetId
	}

	if batch := c.BatchPriority(); batch != nil {
		env["TITUS_BATCH"] = *batch
	}

	if reqIMDSToken := c.RequireIMDSToken(); reqIMDSToken != nil {
		env["TITUS_IMDS_REQUIRE_TOKEN"] = *reqIMDSToken
	}

	envOverrides := c.EnvOverrides()
	for key, value := range envOverrides {
		env[key] = value
	}

	if gpuInfo := c.GPUInfo(); gpuInfo != nil {
		for key, value := range gpuInfo.Env() {
			env[key] = value
		}
	}

	env[TitusRuntimeEnvVariableName] = c.Runtime()

	return env
}

func sortedEnv(env map[string]string) []string {
	retEnv := make([]string, 0, len(env))
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		retEnv = append(retEnv, key+"="+env[key])
	}
	return retEnv
}

// combinedAppStackDetails is a port of the combineAppStackDetails method from frigga.
// See: https://github.com/Netflix/frigga/blob/v0.17.0/src/main/java/com/netflix/frigga/NameBuilder.java
func combinedAppStackDetails(c Container) string {
	if c.JobGroupDetail() != "" {
		return fmt.Sprintf("%s-%s-%s", c.AppName(), c.JobGroupStack(), c.JobGroupDetail())
	}
	if c.JobGroupStack() != "" {
		return fmt.Sprintf("%s-%s", c.AppName(), c.JobGroupStack())
	}
	return c.AppName()
}

func (c *TitusInfoContainer) parseContainerInfoNfsMounts() error {
	efsConfigs := c.titusInfo.GetEfsConfigInfo()
	c.nfsMounts = []NFSMount{}
	if efsConfigs == nil {
		return nil
	}

	for _, efs := range efsConfigs {
		var readOnly bool
		switch efs.GetMntPerms() {
		case titus.ContainerInfo_EfsConfigInfo_RW:
			readOnly = false
		case titus.ContainerInfo_EfsConfigInfo_RO:
			readOnly = true
		case titus.ContainerInfo_EfsConfigInfo_WO:
			readOnly = false
		default:
			return fmt.Errorf("Invalid EFS mount (read/write flag): %+v", efs)
		}

		efsFsID := efs.GetEfsFsId()
		if efsFsID == "" {
			return fmt.Errorf("Invalid EFS mount (empty FS ID): %+v", efs)
		}

		isRealEfsID, err := isEFSID(efsFsID)
		if err != nil {
			return err
		}

		if c.config.AwsRegion == "" {
			return errors.New("AWS region unset")
		}

		nm := NFSMount{
			ServerPath: filepath.Clean(efs.GetEfsFsRelativeMntPoint()),
			MountPoint: filepath.Clean(efs.GetMountPoint()),
			ReadOnly:   readOnly,
		}
		if isRealEfsID {
			nm.Server = fmt.Sprintf("%s.efs.%s.amazonaws.com", efsFsID, c.config.AwsRegion)
		} else {
			// Non-EFS ID: pass in the hostname for the NFS server right on through
			// We are just abusing the "efsID" field to just be the hostname.
			nm.Server = efsFsID
		}

		if nm.ServerPath == "" {
			nm.ServerPath = "/"
		}

		c.nfsMounts = append(c.nfsMounts, nm)
	}

	return nil
}

func isEFSID(FsID string) (bool, error) {
	matched, err := regexp.MatchString(`^fs-[0-9a-f]+$`, FsID)
	if err != nil {
		// The only type of errors that might hit this are regex compile errors
		return false, fmt.Errorf("Something went really wrong determining if '%s' is an EFS ID: %s", FsID, err)
	}
	return matched, nil
}

// GetHumanFriendlyNetworkMode uses the incoming network mode string
// and mutates it a bit to be a environment-variable safe string.
// In the unknown mode, however, we return an empty string for
// the caller to *not* set the variable
func GetHumanFriendlyNetworkMode(mode string) string {
	modeInt := titus.NetworkConfiguration_NetworkMode_value[mode]
	switch modeInt {
	case int32(titus.NetworkConfiguration_UnknownNetworkMode):
		return ""
	case int32(titus.NetworkConfiguration_Ipv4Only):
		return "IPV4_ONLY"
	case int32(titus.NetworkConfiguration_Ipv6AndIpv4):
		return "IPV6_AND_IPV4"
	case int32(titus.NetworkConfiguration_Ipv6AndIpv4Fallback):
		return "IPV6_WITH_TRANSITION"
	case int32(titus.NetworkConfiguration_Ipv6Only):
		return "IPV6_ONLY"
	default:
		return ""
	}
}
