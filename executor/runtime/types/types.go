package types

import "fmt"

import (
	"context"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"

	// The purpose of this is to tell gometalinter to keep vendoring this package
	_ "github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
)

const (
	hostnameStyleParam = "titusParameter.agent.hostnameStyle"
	// FuseEnabledParam is a container atttribute set to enable FUSE
	FuseEnabledParam             = "titusParameter.agent.fuseEnabled"
	assignIPv6AddressParam       = "titusParameter.agent.assignIPv6Address"
	ttyEnabledParam              = "titusParameter.agent.ttyEnabled"
	optimisticIAMTokenFetchParam = "titusParameter.agent.optimisticIAMTokenFetch"
	// TitusEnvironmentsDir is the directory we write Titus environment files and JSON configs to
	TitusEnvironmentsDir            = "/var/lib/titus-environments"
	titusContainerIDEnvVariableName = "TITUS_CONTAINER_ID"
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

// CleanupFunc can be registered to be called on container teardown, errors are reported, but not acted upon
type CleanupFunc func() error

// GPUContainer manages the GPUs for a container, and frees them
type GPUContainer interface {
	Devices() []string
	Deallocate() int
}

// Container contains config state for a container.
// It is not safe to be used concurrently, synchronization and locking needs to be handled externally.
type Container struct {
	// nolint: maligned
	ID        string
	TaskID    string
	Env       map[string]string
	Labels    map[string]string
	Ports     []string
	TitusInfo *titus.ContainerInfo
	Resources *Resources

	// cleanup callbacks that runtime implementations can register to do cleanup
	// after a launchGuard on the taskID has been lifted
	cleanup []CleanupFunc

	// VPC driver fields
	SecurityGroupIDs []string
	// Titus Index 1 = ENI index 0
	Allocation         vpcTypes.Allocation
	NormalizedENIIndex int
	BandwidthLimitMbps uint32

	// Is this container meant to run SystemD?
	IsSystemD bool

	// GPU devices
	GPUInfo GPUContainer

	AllocationCommand       *exec.Cmd
	AllocationCommandStatus chan error
	SetupCommand            *exec.Cmd
	SetupCommandStatus      chan error

	Config config.Config
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
	image := c.TitusInfo.GetImageName()
	baseRef := c.Config.DockerRegistry + "/" + image
	if c.ImageHasDigest() {
		// digest has precedence
		return baseRef + "@" + c.TitusInfo.GetImageDigest()
	}
	return baseRef + ":" + c.TitusInfo.GetVersion()
}

// RegisterRuntimeCleanup calls registered functions whether or not the container successfully starts
func (c *Container) RegisterRuntimeCleanup(callback CleanupFunc) {
	c.cleanup = append(c.cleanup, callback)
}

// RuntimeCleanup runs cleanup callbacks registered by runtime implementations
func (c *Container) RuntimeCleanup() []error {
	var errs []error
	for idx := range c.cleanup {
		fn := c.cleanup[len(c.cleanup)-idx-1]
		if err := fn(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
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
	retEnv := make([]string, 0, len(c.Env))
	keys := make([]string, 0, len(c.Env))
	for k := range c.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		retEnv = append(retEnv, key+"="+c.Env[key])
	}
	return retEnv

}

// GetIamProfile retrieves, and validates the format of the IAM profile
func (c *Container) GetIamProfile() (string, error) {
	if c.TitusInfo.IamProfile == nil || c.TitusInfo.GetIamProfile() == "" {
		return "", ErrMissingIAMRole
	}
	if _, err := arn.Parse(c.TitusInfo.GetIamProfile()); err != nil {
		return "", err
	}

	return c.TitusInfo.GetIamProfile(), nil
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
		hostname := fmt.Sprintf("ip-%s", strings.Replace(c.Allocation.IPV4Address, ".", "-", 3))
		return hostname, nil
	default:
		return "", &InvalidConfigurationError{Reason: fmt.Errorf("Unknown hostname style: %s", hostnameStyle)}
	}
}

// GetFuseEnabled determines whether the container has FUSE devices exposed to it
func (c *Container) GetFuseEnabled() (bool, error) {
	fuseEnabledStr, ok := c.TitusInfo.GetPassthroughAttributes()[FuseEnabledParam]
	if !ok {
		return false, nil
	}
	val, err := strconv.ParseBool(fuseEnabledStr)
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
	c.Env[titusContainerIDEnvVariableName] = c.ID
}

// Resources specify constraints to be applied to a Container
type Resources struct {
	Mem       int64 // in MiB
	CPU       int64
	Disk      uint64
	HostPorts []uint16
}

// NetworkConfigurationDetails used to pass results back to master
type NetworkConfigurationDetails struct {
	IsRoutableIP bool
	IPAddress    string
	EniIPAddress string
	EniID        string
	ResourceID   string
}

// Details contains additional details about a container that are
// not returned by normal container start calls.
type Details struct {
	IPAddresses          map[string]string `json:"ipAddresses,omitempty"`
	NetworkConfiguration *NetworkConfigurationDetails
}

// Runtime is the containerization engine
type Runtime interface {
	// Prepare the host to run a Container: download images, prepare filesystems, etc.
	// Implementations must set *Container.ID to a runtime specific identifier.
	// bindMounts are strings in the Docker format "src:dst:mode"
	// TODO(fabio): better (non-Docker specific) abstraction for binds
	// The context passed to the Prepare, and Start function is valid over the lifetime of the container,
	// NOT per-operation
	Prepare(containerCtx context.Context, c *Container, bindMounts []string, startTime time.Time) error
	// Start a container -- Returns an optional Log Directory if an external Logger is desired
	Start(containerCtx context.Context, c *Container) (string, *Details, <-chan StatusMessage, error)
	// Kill a container
	Kill(*Container) error
	// Cleanup can be called to tear down resources after a container has been Killed
	Cleanup(*Container) error
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
