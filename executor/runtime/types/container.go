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

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/uploader"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/maps"
	ptr "k8s.io/utils/pointer"
)

const (
	appNameLabelKey          = "com.netflix.titus.appName"
	commandLabelKey          = "com.netflix.titus.command"
	entrypointLabelKey       = "com.netflix.titus.entrypoint"
	cpuLabelKey              = "com.netflix.titus.cpu"
	memLabelKey              = "com.netflix.titus.mem"
	diskLabelKey             = "com.netflix.titus.disk"
	networkLabelKey          = "com.netflix.titus.network"
	workloadTypeLabelKey     = "com.netflix.titus.workload.type"
	ownerEmailLabelKey       = "com.netflix.titus.owner.email"
	ownerEmailPassThroughKey = "titus.agent.ownerEmail"
	jobTypeLabelKey          = "com.netflix.titus.job.type"
	jobTypePassThroughKey    = "titus.agent.jobType"
	titusTaskInstanceIDKey   = "TITUS_TASK_INSTANCE_ID"
	titusJobIDKey            = "TITUS_JOB_ID"

	// Passthrough params
	s3WriterRoleParam                = "titusParameter.agent.log.s3WriterRole"
	s3BucketNameParam                = "titusParameter.agent.log.s3BucketName"
	s3PathPrefixParam                = "titusParameter.agent.log.s3PathPrefix"
	hostnameStyleParam               = "titusParameter.agent.hostnameStyle"
	logUploadThresholdTimeParam      = "titusParameter.agent.log.uploadThresholdTime"
	logUploadCheckIntervalParam      = "titusParameter.agent.log.uploadCheckInterval"
	logStdioCheckIntervalParam       = "titusParameter.agent.log.stdioCheckInterval"
	LogKeepLocalFileAfterUploadParam = "titusParameter.agent.log.keepLocalFileAfterUpload"
	FuseEnabledParam                 = "titusParameter.agent.fuseEnabled"
	KvmEnabledParam                  = "titusParameter.agent.kvmEnabled"
	assignIPv6AddressParam           = "titusParameter.agent.assignIPv6Address"
	batchPriorityParam               = "titusParameter.agent.batchPriority"
	serviceMeshEnabledParam          = "titusParameter.agent.service.serviceMesh.enabled"
	serviceMeshContainerParam        = "titusParameter.agent.service.serviceMesh.container"
	ttyEnabledParam                  = "titusParameter.agent.ttyEnabled"
	jumboFrameParam                  = "titusParameter.agent.allowNetworkJumbo"
	AccountIDParam                   = "titusParameter.agent.accountId"
	imdsRequireTokenParam            = "titusParameter.agent.imds.requireToken"
	subnetsParam                     = "titusParameter.agent.subnets"
	elasticIPPoolParam               = "titusParameter.agent.elasticIPPool"
	elasticIPsParam                  = "titusParameter.agent.elasticIPs"

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
	assignIPv6Address  bool
	elasticIPPool      string
	elasticIPs         string
	normalizedENIIndex int
	subnetIDs          string
	useJumboFrames     bool
	vpcAllocation      vpcTypes.HybridAllocation
	vpcAccountID       string

	// Log uploader fields

	logUploadThresholdTime *time.Duration
	logUploadCheckInterval *time.Duration
	logStdioCheckInterval  *time.Duration
	// LogLocalFileAfterUpload indicates whether or not we should delete log files after uploading them
	logKeepLocalFileAfterUpload bool
	logUploadRegexp             *regexp.Regexp
	logUploaderConfig           uploader.Config

	pod *corev1.Pod

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
	kvmEnabled         bool
	requireIMDSToken   string
	serviceMeshEnabled *bool
	serviceMeshImage   string
	ttyEnabled         bool

	config config.Config
}

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, resources Resources, cfg config.Config) (Container, error) {
	return NewContainerWithPod(taskID, titusInfo, resources, cfg, nil)
}

// NewContainerWithPod allocates and initializes a new container struct object. Pod can be optionally passed. If nil, ignored
func NewContainerWithPod(taskID string, titusInfo *titus.ContainerInfo, resources Resources, cfg config.Config, pod *corev1.Pod) (*TitusInfoContainer, error) {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()

	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      taskID,
	}

	if len(titusInfo.GetIamProfile()) > 0 {
		labels["ec2.iam.role"] = titusInfo.GetIamProfile()
	}

	labels[cpuLabelKey] = itoa(resources.CPU)
	labels[memLabelKey] = itoa(resources.Mem)
	labels[diskLabelKey] = itoa(resources.Disk)
	labels[networkLabelKey] = itoa(resources.Network)
	addLabels(titusInfo, labels)

	c := &TitusInfoContainer{
		taskID:       taskID,
		titusInfo:    titusInfo,
		resources:    resources,
		envOverrides: map[string]string{},
		labels:       labels,
		config:       cfg,
	}

	if pod != nil {
		if l := len(pod.Spec.Containers); l != 1 {
			return nil, fmt.Errorf("Pod has unexpected number of containers (not 1): %d", l)
		}
		c.pod = pod.DeepCopy()
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

	if err := parseEntryPointAndCommand(titusInfo, c); err != nil {
		return nil, err
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

	// This depends on a number of the other fields being populated, so run it last
	cEnv := c.Env()
	c.labels[titusTaskInstanceIDKey] = cEnv[titusTaskInstanceIDKey]
	c.jobID = cEnv[titusJobIDKey]

	return c, nil
}

func addLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	labels = addContainerLabels(containerInfo, labels)
	labels = addPassThroughLabels(containerInfo, labels)
	labels = addProcessLabels(containerInfo, labels)
	return labels
}

func addContainerLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	labels[appNameLabelKey] = containerInfo.GetAppName()

	workloadType := StaticWorkloadType
	if containerInfo.GetAllowCpuBursting() {
		workloadType = BurstWorkloadType
	}

	labels[workloadTypeLabelKey] = string(workloadType)

	return labels
}

func addPassThroughLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	ownerEmail := ""
	jobType := ""

	passthroughAttributes := containerInfo.GetPassthroughAttributes()
	if passthroughAttributes != nil {
		ownerEmail = passthroughAttributes[ownerEmailPassThroughKey]
		jobType = passthroughAttributes[jobTypePassThroughKey]
	}

	labels[ownerEmailLabelKey] = ownerEmail
	labels[jobTypeLabelKey] = jobType

	return labels
}

func addProcessLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	process := containerInfo.GetProcess()
	if process != nil {
		entryPoint := process.GetEntrypoint()
		if entryPoint != nil {
			entryPointStr := strings.Join(entryPoint[:], " ")
			labels[entrypointLabelKey] = entryPointStr
		}

		command := process.GetCommand()
		if command != nil {
			commandStr := strings.Join(entryPoint[:], " ")
			labels[commandLabelKey] = commandStr
		}
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

func (c *TitusInfoContainer) AppName() string {
	return c.titusInfo.GetAppName()
}

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

// CombinedAppStackDetails is a port of the combineAppStackDetails method from frigga.
// See: https://github.com/Netflix/frigga/blob/v0.17.0/src/main/java/com/netflix/frigga/NameBuilder.java
func (c *TitusInfoContainer) CombinedAppStackDetails() string {
	if c.JobGroupDetail() != "" {
		return fmt.Sprintf("%s-%s-%s", c.AppName(), c.JobGroupStack(), c.JobGroupDetail())
	}
	if c.JobGroupStack() != "" {
		return fmt.Sprintf("%s-%s", c.AppName(), c.JobGroupStack())
	}
	return c.AppName()
}

// ComputeHostname computes a hostname in the container using container ID or ec2 style
// depending on titusParameter.agent.hostnameStyle setting.  Return error if style is unrecognized.
func (c *TitusInfoContainer) ComputeHostname() (string, error) {
	hostnameStyle := strings.ToLower(c.hostnameStyle)
	switch hostnameStyle {
	case "":
		return strings.ToLower(c.TaskID()), nil
	case "ec2":
		hostname := fmt.Sprintf("ip-%s", strings.Replace(c.vpcAllocation.IPV4Address.Address.Address, ".", "-", 3))
		return hostname, nil
	default:
		return "", &InvalidConfigurationError{Reason: fmt.Errorf("Unknown hostname style: %s", hostnameStyle)}
	}
}

// Config returns the container config with all necessary fields for validating its identity with Metatron
func (c *TitusInfoContainer) Config(startTime time.Time) (*titus.ContainerInfo, error) {
	launchTime := uint64(startTime.Unix())
	ti := c.titusInfo
	containerHostname, err := c.ComputeHostname()
	if err != nil {
		return nil, err
	}

	if ti.GetRunState() == nil {
		ti.RunState = &titus.RunningContainerInfo{}
	}

	if ti.RunState.LaunchTimeUnixSec == nil {
		ti.RunState.LaunchTimeUnixSec = &launchTime
	}
	if ti.RunState.TaskId == nil {
		ti.RunState.TaskId = &c.taskID
	}
	if ti.RunState.HostName == nil {
		ti.RunState.HostName = &containerHostname
	}

	var cmd []string
	var entrypoint []string

	// The identity server looks at the Process object for the entrypoint. For legacy apps
	// that pass entrypoint as a string, use the whole string as the entrypoint rather than
	// parsing it: this matches how the entrypoint is signed in the first place.
	//
	// See Process() above for more details.
	if ti.EntrypointStr != nil {
		entrypoint = append(entrypoint, *ti.EntrypointStr)
	} else {
		entrypoint, cmd = c.Process()
	}

	ti.Process = &titus.ContainerInfo_Process{
		Entrypoint: entrypoint,
		Command:    cmd,
	}

	return ti, nil
}

func (c *TitusInfoContainer) Capabilities() *titus.ContainerInfo_Capabilities {
	return c.titusInfo.GetCapabilities()
}

func (c *TitusInfoContainer) EfsConfigInfo() []*titus.ContainerInfo_EfsConfigInfo {
	return c.titusInfo.GetEfsConfigInfo()
}

func (c *TitusInfoContainer) ElasticIPPool() *string {
	return strPtrOr(c.elasticIPPool, nil)
}

func (c *TitusInfoContainer) ElasticIPs() *string {
	return strPtrOr(c.elasticIPs, nil)
}

func (c *TitusInfoContainer) Env() map[string]string {
	// Order goes (least priority, to highest priority:
	// -Hard coded environment variables
	// -Copied environment variables from the host
	// -Resource env variables
	// -User provided environment in POD (if pod unset, then fall back to containerinfo)
	// -Network Config
	// -Executor overrides

	// Hard coded (in executor config)
	env := c.config.GetHardcodedEnv()

	// Env copied from host
	for key, value := range c.config.GetEnvFromHost() {
		env[key] = value
	}

	resources := c.Resources()
	// Resource environment variables
	env["TITUS_NUM_MEM"] = itoa(resources.Mem)
	env["TITUS_NUM_CPU"] = itoa(resources.CPU)
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
	// passed environment
	passedEnv := func() map[string]string {
		containerInfoEnv := map[string]string{
			"TITUS_ENV_FROM": "containerInfo",
		}
		for key, value := range c.titusInfo.GetUserProvidedEnv() {
			if value != "" {
				env[key] = value
			}
		}
		for key, value := range c.titusInfo.GetTitusProvidedEnv() {
			env[key] = value
		}

		if c.pod == nil {
			return containerInfoEnv
		}
		// This is a "dumb" check -- that just makes sure 1 container exists so we don't null pointer exception
		// We probably don't want to blindly source env
		if len(c.pod.Spec.Containers) != 1 {
			return containerInfoEnv
		}
		if len(c.pod.Spec.Containers[0].Env) == 0 {
			return containerInfoEnv
		}

		podEnv := map[string]string{
			"TITUS_ENV_FROM": "pod",
		}
		for _, val := range c.pod.Spec.Containers[0].Env {
			podEnv[val.Name] = val.Value
		}
		if val, ok := podEnv[titusTaskInstanceIDKey]; !ok {
			// We need to have the pod env have this variable
			return containerInfoEnv
		} else if val == "" {
			return containerInfoEnv
		}
		return podEnv
	}()

	for key, value := range passedEnv {
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

	env["NETFLIX_APP"] = c.AppName()
	env["TITUS_IAM_ROLE"] = ptr.StringPtrDerefOr(c.IamRole(), "")

	if c.config.MetatronEnabled {
		// When set, the metadata service will return signed identity documents suitable for bootstrapping Metatron
		env[metadataserverTypes.TitusMetatronVariableName] = True
	} else {
		env[metadataserverTypes.TitusMetatronVariableName] = False
	}

	if c.vpcAllocation.IPV4Address != nil {
		env["EC2_LOCAL_IPV4"] = c.vpcAllocation.IPV4Address.Address.Address
	}

	if c.vpcAllocation.IPV6Address != nil {
		env["EC2_IPV6S"] = c.vpcAllocation.IPV6Address.Address.Address
	}

	// Heads up, this doesn't work in generation v1 instances of VPC Service
	env["EC2_VPC_ID"] = c.vpcAllocation.BranchENIVPC
	env["EC2_INTERFACE_ID"] = c.vpcAllocation.BranchENIID
	env["EC2_SUBNET_ID"] = c.vpcAllocation.BranchENISubnet

	if batch := c.BatchPriority(); batch != nil {
		env["TITUS_BATCH"] = *batch
	}

	if reqIMDSToken := c.RequireIMDSToken(); reqIMDSToken != nil {
		env["TITUS_IMDS_REQUIRE_TOKEN"] = *reqIMDSToken
	}

	c.envLock.Lock()
	envOverrides := maps.CopySS(c.envOverrides)
	c.envLock.Unlock()

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

func (c *TitusInfoContainer) FuseEnabled() bool {
	return c.fuseEnabled
}

func (c *TitusInfoContainer) GPUInfo() GPUContainer {
	return c.gpuInfo
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

func (c *TitusInfoContainer) SetVPCAllocation(allocation *vpcTypes.HybridAllocation) {
	c.vpcAllocation = *allocation
}

// ShmSizeMiB determines the container's /dev/shm size
func (c *TitusInfoContainer) ShmSizeMiB() *uint32 {
	shmSize := c.titusInfo.GetShmSizeMB()
	if shmSize != 0 {
		return &shmSize
	}
	return nil
}

func (c *TitusInfoContainer) SidecarConfigs() (map[string]*SidecarContainerConfig, error) {
	scMap := make(map[string]*SidecarContainerConfig)
	svcMeshImage := ""
	if c.ServiceMeshEnabled() {
		img, err := c.serviceMeshImageName()
		if err != nil {
			return scMap, err
		}
		svcMeshImage = img
	}

	imageMap := map[string]string{
		SidecarServiceAbMetrix:    c.config.AbmetrixServiceImage,
		SidecarServiceLogViewer:   c.config.LogViewerServiceImage,
		SidecarServiceMetatron:    c.config.MetatronServiceImage,
		SidecarServiceServiceMesh: svcMeshImage,
		SidecarServiceSshd:        c.config.SSHDServiceImage,
	}

	for _, sc := range sideCars {
		sc.Image = path.Join(c.config.DockerRegistry, imageMap[sc.ServiceName])
		scAddr := sc
		scMap[sc.ServiceName] = &scAddr
		log.Infof("sidecar name=%s image=%s", sc.ServiceName, sc.Image)
	}

	return scMap, nil
}

func (c *TitusInfoContainer) SignedAddressAllocationUUID() *string {
	if c.titusInfo.SignedAddressAllocation != nil {
		return &c.titusInfo.SignedAddressAllocation.AddressAllocation.Uuid
	}

	return nil
}

// GetSortedEnvArray returns the list of environment variables set for the container as a sorted Key=Value list
func (c *TitusInfoContainer) SortedEnvArray() []string {
	env := c.Env()
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

func (c *TitusInfoContainer) SubnetIDs() *string {
	return strPtrOr(c.subnetIDs, nil)
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

func (c *TitusInfoContainer) VPCAllocation() *vpcTypes.HybridAllocation {
	return &c.vpcAllocation
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
func parseEntryPointAndCommand(titusInfo *titus.ContainerInfo, c *TitusInfoContainer) error {
	if titusInfo.EntrypointStr != nil { // nolint: staticcheck
		// deprecated (old) way of passing entrypoints as a flat string. We need to parse it
		entrypoint, err := dockershellparser.ProcessWords(titusInfo.GetEntrypointStr(), []string{}) // nolint: megacheck
		if err != nil {
			return err
		}

		// nil cmd because everything is in the entrypoint
		c.entrypoint = entrypoint
		return nil
	}

	process := titusInfo.GetProcess()
	c.command = process.GetCommand()
	c.entrypoint = process.GetEntrypoint()
	return nil
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
