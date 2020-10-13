package types

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/util/maps"

	// The purpose of this is to tell gometalinter to keep vendoring this package
	_ "github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
	"github.com/pkg/errors"
)

const (
	hostnameStyleParam = "titusParameter.agent.hostnameStyle"
	// FuseEnabledParam is a container atttribute set to enable FUSE
	FuseEnabledParam             = "titusParameter.agent.fuseEnabled"
	KvmEnabledParam              = "titusParameter.agent.kvmEnabled"
	assignIPv6AddressParam       = "titusParameter.agent.assignIPv6Address"
	serviceMeshEnabledParam      = "titusParameter.agent.service.serviceMesh.enabled"
	serviceMeshContainerParam    = "titusParameter.agent.service.serviceMesh.container"
	ttyEnabledParam              = "titusParameter.agent.ttyEnabled"
	optimisticIAMTokenFetchParam = "titusParameter.agent.optimisticIAMTokenFetch"
	jumboFrameParam              = "titusParameter.agent.allowNetworkJumbo"
	AccountIDParam               = "titusParameter.agent.accountId"
	imdsRequireTokenParam        = "titusParameter.agent.imds.requireToken"

	// TitusEnvironmentsDir is the directory we write Titus environment files and JSON configs to
	TitusEnvironmentsDir            = "/var/lib/titus-environments"
	titusContainerIDEnvVariableName = "TITUS_CONTAINER_ID"
	// TitusRuntimeEnvVariableName is used to pass the name of the oci-compliant runtime used to run a container.
	// This can be used to construct the root path for runc to use to run system services.
	TitusRuntimeEnvVariableName = "TITUS_OCI_RUNTIME"

	// DefaultOciRuntime is the default oci-compliant runtime used to run system services
	DefaultOciRuntime = "runc"

	// VPCIPv4Label is the VPC address of the container.
	//
	// Deprecated: Titus does not support non-VPC addresses, so NetIPv4Label
	// should be used instead
	VPCIPv4Label = "titus.vpc.ipv4"

	// NetIPv4Label is the canonical network address of the container
	NetIPv4Label = "titus.net.ipv4"
)

const (
	logUploadThresholdTimeParam = "titusParameter.agent.log.uploadThresholdTime"
	logUploadCheckIntervalParam = "titusParameter.agent.log.uploadCheckInterval"
	logStdioCheckIntervalParam  = "titusParameter.agent.log.stdioCheckInterval"
	// LogKeepLocalFileAfterUploadParam is the container attribute to specify whether the log file rotator should delete files after uploading
	LogKeepLocalFileAfterUploadParam = "titusParameter.agent.log.keepLocalFileAfterUpload"

	defaultLogUploadThresholdTime = 6 * time.Hour
	defaultLogUploadCheckInterval = 15 * time.Minute
	defaultStdioLogCheckInterval  = 1 * time.Minute
)

// ErrMissingIAMRole indicates that the Titus job was submitted without an IAM role
// This is a transition because previously the protobuf had this marked as an optional field
// and it's a temporary measure during protocol evolution.
var ErrMissingIAMRole = errors.New("IAM Role Missing")

// RegistryImageNotFoundError represents an error where an image
// did not exist in the registry
type RegistryImageNotFoundError struct {
	Reason error
}

// Error return a string describing the error
func (e *RegistryImageNotFoundError) Error() string {
	return fmt.Sprintf("Image does not exist in registry : %s", e.Reason)
}

// BadEntryPointError represents an error where the provided
// entrypoint is not valid.
type BadEntryPointError struct {
	Reason error
}

// Error returns a string describing an error
func (e *BadEntryPointError) Error() string {
	return fmt.Sprintf("Bad entry point : %s", e.Reason)
}

// InvalidSecurityGroupError represents an error where the provided
// security group is not valid.
type InvalidSecurityGroupError struct {
	Reason error
}

// Error returns a string describing an error
func (e *InvalidSecurityGroupError) Error() string {
	return fmt.Sprintf("Invalid security group : %s", e.Reason)
}

// InvalidConfigurationError represents invalid configuration
// that results in a task startup being aborted
type InvalidConfigurationError struct {
	Reason error
}

// Error returns a string describing an error
func (e *InvalidConfigurationError) Error() string {
	return fmt.Sprintf("Invalid configuration: %s", e.Reason)
}

type GPUManager interface {
	AllocDevices(ctx context.Context, n int) (GPUContainer, error)
}

// GPUContainer manages the GPUs for a container, and frees them
type GPUContainer interface {
	Devices() []string
	// Deallocate GPU Container. Must be idempotent.
	Deallocate() int
	Runtime() string
	// Env returns any GPU specific environment overrides required
	Env() map[string]string
}

// Container contains config state for a container. It should be Read Only. It should only be initialized via a
// constructor, and not directly.
type Container struct {
	// ID is the container ID (in Docker). It is set by the container runtime after starting up.
	ID      string
	TaskID  string
	envLock sync.Mutex
	// envOverrides are set by the executor for things like IPv4 / IPv6 address
	envOverrides map[string]string
	Labels       map[string]string
	TitusInfo    *titus.ContainerInfo
	Resources    Resources

	// VPC driver fields
	SecurityGroupIDs   []string
	Allocation         vpcTypes.HybridAllocation
	NormalizedENIIndex int
	BandwidthLimitMbps int64
	AllocationUUID     string

	// Is this container meant to run SystemD?
	IsSystemD bool

	pod *corev1.Pod

	// GPU devices
	gpuInfo GPUContainer
	// Set if using a non-runc runtime to run system service init commands
	runtime string

	iamRole string

	Config config.Config
}

func (c *Container) VPCAccountID() string {
	if vpcAccountID, ok := c.TitusInfo.GetPassthroughAttributes()[AccountIDParam]; ok {
		return vpcAccountID
	}

	// If the param wasn't passed via pass through attributes, then fall back to pulling it from the host env
	return c.Config.EC2AccountID
}

// combineAppStackDetails is a port of the method with the same name from frigga.
// See: https://github.com/Netflix/frigga/blob/v0.17.0/src/main/java/com/netflix/frigga/NameBuilder.java
func combineAppStackDetails(taskInfo *titus.ContainerInfo) string {
	var (
		stack   = taskInfo.GetJobGroupStack()
		details = taskInfo.GetJobGroupDetail()
		appName = taskInfo.GetAppName()
	)
	if details != "" {
		return fmt.Sprintf("%s-%s-%s", appName, stack, details)
	}
	if stack != "" {
		return fmt.Sprintf("%s-%s", appName, stack)
	}
	return appName
}

func (c *Container) GetEnv() map[string]string {
	// Order goes (least priority, to highest priority:
	// -Hard coded environment variables
	// -Copied environment variables from the host
	// -Resource env variables
	// -User provided environment in POD (if pod unset, then fall back to containerinfo)
	// -Network Config
	// -Executor overrides

	// Hard coded (in executor config)
	env := c.Config.GetHardcodedEnv()

	// Env copied from host
	for key, value := range c.Config.GetEnvFromHost() {
		env[key] = value
	}

	// Resource environment variables
	env["TITUS_NUM_MEM"] = itoa(c.Resources.Mem)
	env["TITUS_NUM_CPU"] = itoa(c.Resources.CPU)
	env["TITUS_NUM_DISK"] = itoa(c.Resources.Disk)
	env["TITUS_NUM_NETWORK_BANDWIDTH"] = itoa(c.Resources.Network)

	if name := c.TitusInfo.GetImageName(); name != "" {
		env["TITUS_IMAGE_NAME"] = name
	}
	if tag := c.TitusInfo.GetVersion(); tag != "" {
		env["TITUS_IMAGE_TAG"] = tag
	}
	if digest := c.TitusInfo.GetImageDigest(); digest != "" {
		env["TITUS_IMAGE_DIGEST"] = digest
	}

	env["EC2_OWNER_ID"] = c.VPCAccountID()

	cluster := combineAppStackDetails(c.TitusInfo)
	env["NETFLIX_APP"] = c.TitusInfo.GetAppName()
	env["NETFLIX_CLUSTER"] = cluster
	env["NETFLIX_STACK"] = c.TitusInfo.GetJobGroupStack()
	env["NETFLIX_DETAIL"] = c.TitusInfo.GetJobGroupDetail()

	var asgName string
	if seq := c.TitusInfo.GetJobGroupSequence(); seq == "" {
		asgName = cluster + "-v000"
	} else {
		asgName = cluster + "-" + seq
	}
	env["NETFLIX_AUTO_SCALE_GROUP"] = asgName
	env["TITUS_IAM_ROLE"] = c.iamRole

	// passed environment
	passedEnv := func() map[string]string {
		containerInfoEnv := map[string]string{
			"TITUS_ENV_FROM": "containerInfo",
		}
		for key, value := range c.TitusInfo.GetUserProvidedEnv() {
			if value != "" {
				env[key] = value
			}
		}
		for key, value := range c.TitusInfo.GetTitusProvidedEnv() {
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
			if val.Value != "" {
				podEnv[val.Name] = val.Value
			}
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

	if c.Config.MetatronEnabled {
		// When set, the metadata service will return signed identity documents suitable for bootstrapping Metatron
		env[metadataserverTypes.TitusMetatronVariableName] = "true"
	} else {
		env[metadataserverTypes.TitusMetatronVariableName] = "false"
	}

	if c.Allocation.IPV4Address != nil {
		env["EC2_LOCAL_IPV4"] = c.Allocation.IPV4Address.Address.Address
	}

	if c.Allocation.IPV6Address != nil {
		env["EC2_IPV6S"] = c.Allocation.IPV6Address.Address.Address
	}

	// Heads up, this doesn't work in generation v1 instances of VPC Service
	env["EC2_VPC_ID"] = c.Allocation.BranchENIVPC
	env["EC2_INTERFACE_ID"] = c.Allocation.BranchENIID
	env["EC2_SUBNET_ID"] = c.Allocation.BranchENISubnet

	if batch := c.GetBatch(); batch != nil {
		env["TITUS_BATCH"] = *batch
	}

	if requireToken, ok := c.TitusInfo.GetPassthroughAttributes()[imdsRequireTokenParam]; ok {
		env["TITUS_IMDS_REQUIRE_TOKEN"] = requireToken
	}

	c.envLock.Lock()
	envOverrides := maps.CopySS(c.envOverrides)
	c.envLock.Unlock()

	for key, value := range envOverrides {
		env[key] = value
	}

	if gpuInfo := c.GetGPUInfo(); gpuInfo != nil {
		for key, value := range gpuInfo.Env() {
			env[key] = value
		}
	}

	env[TitusRuntimeEnvVariableName] = c.GetRuntime()
	return env
}

func (c *Container) SetEnv(key, value string) {
	c.envLock.Lock()
	defer c.envLock.Unlock()
	c.envOverrides[key] = value
}

func (c *Container) SetEnvs(env map[string]string) {
	c.envLock.Lock()
	defer c.envLock.Unlock()
	for key, value := range env {
		c.envOverrides[key] = value
	}
}

func (c *Container) GetGPUInfo() GPUContainer {
	return c.gpuInfo
}

func (c *Container) SetGPUInfo(gpuInfo GPUContainer) {
	c.gpuInfo = gpuInfo
}

func (c *Container) GetRuntime() string {
	if c.gpuInfo != nil {
		return c.gpuInfo.Runtime()
	}
	return c.runtime
}

// ImageHasDigest returns true if the image was specified by digest
func (c *Container) ImageHasDigest() bool {
	digest := c.TitusInfo.GetImageDigest()
	return digest != ""
}

// QualifiedImageName appends the registry and version to the Image name
func (c *Container) QualifiedImageName() string {
	if c == nil {
		return ""
	}
	baseRef := c.TitusInfo.GetFullyQualifiedImage()
	if baseRef == "" {
		image := c.TitusInfo.GetImageName()
		baseRef = c.Config.DockerRegistry + "/" + image
	}
	if c.ImageHasDigest() {
		// digest has precedence
		return baseRef + "@" + c.TitusInfo.GetImageDigest()
	}
	return baseRef + ":" + c.TitusInfo.GetVersion()
}

// ImageTagForMetrics returns a map with the image name
func (c *Container) ImageTagForMetrics() map[string]string {
	return map[string]string{"image": *c.TitusInfo.ImageName}
}

// UploadDir hold files that will by uploaded by log uploaders
func (c *Container) UploadDir(namespace string) string {
	return filepath.Join("titan", c.Config.Stack, namespace, c.TaskID)
}

// Process extracts Entrypoint and Cmd from TitusInfo expecting that only one of the below will be present:
//
// - TitusInfo.EntrypointStr, the old code path being deprecated. The flat string will be parsed according to shell
//   rules and be returned as entrypoint, while cmd will be nil
// - TitusInfo.Process, the new code path where both entrypoint and cmd are lists. Docker rules on how they interact
//   apply
//
// If both are set, EntrypointStr has precedence to allow for smoother transition.
func (c *Container) Process() (entrypoint, cmd []string, err error) {
	if c.TitusInfo.EntrypointStr != nil {
		// deprecated (old) way of passing entrypoints as a flat string. We need to parse it
		entrypoint, err = dockershellparser.ProcessWords(c.TitusInfo.GetEntrypointStr(), []string{}) // nolint: megacheck
		if err != nil {
			return nil, nil, err
		}
		// nil cmd because everything is in the entrypoint
		return entrypoint, nil, err
	}

	process := c.TitusInfo.GetProcess()
	return process.GetEntrypoint(), process.GetCommand(), nil
}

// GetSortedEnvArray returns the list of environment variables set for the container as a sorted Key=Value list
func (c *Container) GetSortedEnvArray() []string {
	env := c.GetEnv()
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

// GetIamProfile retrieves, and validates the format of the IAM profile
func (c *Container) GetIamProfile() string {
	return c.iamRole
}

// GetBatch returns what the environment variable TITUS_BATCH should be set to.
// if it returns nil, TITUS_BATCH should be unset
func (c *Container) GetBatch() *string {
	idleStr := "idle"
	trueStr := "true"

	if c.Resources.CPU == 0 {
		return &idleStr
	}

	if !c.TitusInfo.GetBatch() {
		return nil
	}

	if c.TitusInfo.GetPassthroughAttributes()["titusParameter.agent.batchPriority"] == "idle" {
		return &idleStr
	}

	return &trueStr
}

// ComputeHostname computes a hostname in the container using container ID or ec2 style
// depending on titusParameter.agent.hostnameStyle setting.  Return error if style is unrecognized.
func (c *Container) ComputeHostname() (string, error) {
	hostnameStyle := strings.ToLower(c.TitusInfo.GetPassthroughAttributes()[hostnameStyleParam])
	switch hostnameStyle {
	case "":
		return strings.ToLower(c.TaskID), nil
	case "ec2":
		hostname := fmt.Sprintf("ip-%s", strings.Replace(c.Allocation.IPV4Address.Address.Address, ".", "-", 3))
		return hostname, nil
	default:
		return "", &InvalidConfigurationError{Reason: fmt.Errorf("Unknown hostname style: %s", hostnameStyle)}
	}
}

// GetFuseEnabled determines whether the container has FUSE devices exposed to it
func (c *Container) GetFuseEnabled() (bool, error) {
	return c.GetPassthroughEnabled(FuseEnabledParam)
}

// GetKvmEnabled determines whether the container has KVM exposed to it
func (c *Container) GetKvmEnabled() (bool, error) {
	return c.GetPassthroughEnabled(KvmEnabledParam)
}

func (c *Container) GetPassthroughEnabled(key string) (bool, error) {
	value, ok := c.TitusInfo.GetPassthroughAttributes()[key]

	if !ok {
		return false, nil
	}
	val, err := strconv.ParseBool(value)
	if err != nil {
		return false, err
	}

	return val, nil
}

// AssignIPv6Address determines whether the container should be assigned an IPv6 address
func (c *Container) AssignIPv6Address() (bool, error) {
	assignIPv6AddressStr, ok := c.TitusInfo.GetPassthroughAttributes()[assignIPv6AddressParam]
	if !ok {
		return false, nil
	}
	val, err := strconv.ParseBool(assignIPv6AddressStr)
	if err != nil {
		return false, err
	}

	return val, nil
}

// Jumbo determines whether the container should get jumbo frames
func (c *Container) Jumbo() (bool, error) {
	val, ok := c.TitusInfo.GetPassthroughAttributes()[jumboFrameParam]
	if !ok {
		return false, nil
	}
	allowJumbo, err := strconv.ParseBool(val)
	if err != nil {
		err = fmt.Errorf("Cannot parse value %q of: %s: %w", val, jumboFrameParam, err)
		return false, err
	}

	return allowJumbo, nil
}

// GetServiceMeshEnabled should the service mesh system service be enabled?
func (c *Container) GetServiceMeshEnabled() (bool, error) {
	if !c.Config.ContainerServiceMeshEnabled {
		return false, nil
	}

	enabledStr, ok := c.TitusInfo.GetPassthroughAttributes()[serviceMeshEnabledParam]
	if !ok {
		return false, nil
	}
	val, err := strconv.ParseBool(enabledStr)
	if err != nil {
		return false, err
	}

	return val, nil
}

func (c *Container) GetServiceMeshImage() (string, error) {
	container, ok := c.TitusInfo.GetPassthroughAttributes()[serviceMeshContainerParam]
	if !ok {
		container = c.Config.ProxydServiceImage
	}

	if container == "" {
		return "no-container", errors.New("Could not determine proxyd image")
	}

	return path.Join(c.Config.DockerRegistry, container), nil
}

// GetShmSize should the container's /dev/shm size be set?
func (c *Container) GetShmSize() uint32 {
	return c.TitusInfo.GetShmSizeMB()
}

// GetTty should the container be assigned a tty?
func (c *Container) GetTty() (bool, error) {
	ttyEnabledStr, ok := c.TitusInfo.GetPassthroughAttributes()[ttyEnabledParam]
	if !ok {
		return false, nil
	}
	val, err := strconv.ParseBool(ttyEnabledStr)
	if err != nil {
		return false, err
	}

	return val, nil
}

// GetLogUploadThresholdTime indicates how long since a file was modified before we should upload it and delete it
func (c *Container) GetLogUploadThresholdTime() (time.Duration, error) {
	logUploadThresholdTimeStr, ok := c.TitusInfo.GetPassthroughAttributes()[logUploadThresholdTimeParam]
	if !ok {
		return defaultLogUploadThresholdTime, nil
	}
	duration, err := time.ParseDuration(logUploadThresholdTimeStr)
	if err != nil {
		return 0, errors.Wrap(err, "Cannot parse log upload threshold time")
	}
	// Must be at least 2 * logUploadCheckInterval
	logUploadCheckInterval, err := c.GetLogUploadCheckInterval()
	if err != nil {
		return 0, err
	}
	if duration <= logUploadCheckInterval*2 {
		return 0, fmt.Errorf("Log upload threshold time %s must be at least 2 * %s, the log upload check interval", duration, logUploadCheckInterval)
	}
	logStdioCheckInterval, err := c.GetLogStdioCheckInterval()
	if err != nil {
		return 0, err
	}
	if duration <= logStdioCheckInterval*2 {
		return 0, fmt.Errorf("Log upload threshold time %s must be at least 2 * %s, the stdio check interval", duration, logUploadCheckInterval)
	}

	return duration, nil
}

// GetLogUploadCheckInterval indicates how often we should scan the continers log directory to see if files need to be uploaded
func (c *Container) GetLogUploadCheckInterval() (time.Duration, error) {
	logUploadCheckIntervalStr, ok := c.TitusInfo.GetPassthroughAttributes()[logUploadCheckIntervalParam]
	if !ok {
		return defaultLogUploadCheckInterval, nil
	}
	duration, err := time.ParseDuration(logUploadCheckIntervalStr)
	if err != nil {
		return 0, errors.Wrap(err, "Cannot parse log upload check interval")
	}
	if duration < time.Minute {
		return 0, fmt.Errorf("Log upload check interval '%s' must be at least 1 minute", duration)
	}
	return duration, nil
}

// GetLogStdioCheckInterval indicates how often we should scan the stdio log files to determine whether they should be uploaded
func (c *Container) GetLogStdioCheckInterval() (time.Duration, error) {
	logStdioCheckIntervalStr, ok := c.TitusInfo.GetPassthroughAttributes()[logStdioCheckIntervalParam]
	if !ok {
		return defaultStdioLogCheckInterval, nil
	}
	duration, err := time.ParseDuration(logStdioCheckIntervalStr)
	if err != nil {
		return 0, errors.Wrap(err, "Cannot parse log stdio check interval")
	}
	return duration, nil
}

// GetKeepLocalFileAfterUpload indicates whether or not we should delete log files after uploading them
func (c *Container) GetKeepLocalFileAfterUpload() (bool, error) {
	keepLocalFileAfterUploadStr, ok := c.TitusInfo.GetPassthroughAttributes()[LogKeepLocalFileAfterUploadParam]
	if !ok {
		return false, nil
	}
	return strconv.ParseBool(keepLocalFileAfterUploadStr)
}

// GetOptimisticIAMTokenFetch indicates whether or not we should delete log files after uploading them
func (c *Container) GetOptimisticIAMTokenFetch() (bool, error) {
	optimisticIAMTokenFetchStr, ok := c.TitusInfo.GetPassthroughAttributes()[optimisticIAMTokenFetchParam]
	if !ok {
		return false, nil
	}
	return strconv.ParseBool(optimisticIAMTokenFetchStr)
}

// GetConfig returns the container config with all necessary fields for validating its identity with Metatron
func (c *Container) GetConfig(startTime time.Time) (*titus.ContainerInfo, error) {
	launchTime := uint64(startTime.Unix())
	ti := c.TitusInfo
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
		ti.RunState.TaskId = &c.TaskID
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
		entrypoint, cmd, err = c.Process()
		if err != nil {
			return nil, err
		}
	}

	ti.Process = &titus.ContainerInfo_Process{
		Entrypoint: entrypoint,
		Command:    cmd,
	}

	return ti, nil
}

// SetID sets the container ID for this container, updating internal data structures as necessary
func (c *Container) SetID(id string) {
	c.ID = id
	c.SetEnv(titusContainerIDEnvVariableName, c.ID)
}

// Resources specify constraints to be applied to a Container
type Resources struct {
	Mem     int64 // in MiB
	CPU     int64
	GPU     int64
	Disk    int64
	Network int64
}

// NetworkConfigurationDetails used to pass results back to master
type NetworkConfigurationDetails struct {
	IsRoutableIP   bool
	IPAddress      string
	EniIPAddress   string
	EniIPv6Address string
	EniID          string
	ResourceID     string
}

func (n *NetworkConfigurationDetails) ToMap() map[string]string {
	m := make(map[string]string)
	m["IsRoutableIp"] = strconv.FormatBool(n.IsRoutableIP)
	m["IpAddress"] = n.IPAddress
	m["EniIpAddress"] = n.EniIPAddress
	m["EniId"] = n.EniID
	m["ResourceId"] = n.ResourceID
	if n.EniIPv6Address != "" {
		m["EniIPv6Address"] = n.EniIPv6Address
	}

	return m
}

// Details contains additional details about a container that are
// not returned by normal container start calls.
type Details struct {
	IPAddresses          map[string]string `json:"ipAddresses,omitempty"`
	NetworkConfiguration *NetworkConfigurationDetails
}

type ContainerRuntimeProvider func(ctx context.Context, c *Container, startTime time.Time) (Runtime, error)

// Runtime is the containerization engine
type Runtime interface {
	// Prepare the host to run a Container: download images, prepare filesystems, etc.
	// Implementations must set *Container.ID to a runtime specific identifier.
	// bindMounts are strings in the Docker format "src:dst:mode"
	// TODO(fabio): better (non-Docker specific) abstraction for binds
	// The context passed to the Prepare, and Start function is valid over the lifetime of the container,
	// NOT per-operation
	Prepare(containerCtx context.Context) error
	// Start a container -- Returns an optional Log Directory if an external Logger is desired
	Start(containerCtx context.Context) (string, *Details, <-chan StatusMessage, error)
	// Kill a container. MUST be idempotent.
	Kill(ctx context.Context) error
	// Cleanup can be called to tear down resources after a container has been Killed or has naturally
	// stopped. Must always be called.
	Cleanup(ctx context.Context) error
}

// Status represent a containers state
type Status int

// Possible Container status
const (
	StatusUnknown = Status(iota)
	StatusRunning
	StatusFinished
	StatusFailed
)

// StatusMessage encapsulated the message code + string to send back to the master
type StatusMessage struct {
	Status Status
	Msg    string
}
