package types

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/uploader"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"google.golang.org/protobuf/proto"

	// The purpose of this is to tell gometalinter to keep vendoring this package
	_ "github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus"
	"github.com/pkg/errors"
)

const (
	// TitusEnvironmentsDir is the directory we write Titus environment files and JSON configs to
	TitusEnvironmentsDir            = "/var/lib/titus-environments"
	titusContainerIDEnvVariableName = "TITUS_CONTAINER_ID"
	// TitusRuntimeEnvVariableName is used to pass the name of the oci-compliant runtime used to run a container.
	// This can be used to construct the root path for runc to use to run system services.
	TitusRuntimeEnvVariableName = "TITUS_OCI_RUNTIME"

	// VPCIPv4Label is the VPC address of the container.
	//
	// Deprecated: Titus does not support non-VPC addresses, so NetIPv4Label
	// should be used instead
	VPCIPv4Label = "titus.vpc.ipv4"
	// NetIPv4Label is the canonical network address of the container
	NetIPv4Label = "titus.net.ipv4"

	// Make the linter happy
	True             = "true"
	False            = "false"
	ec2HostnameStyle = "ec2"
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

type SidecarContainerConfig struct {
	ServiceName string
	Image       string
	Volumes     map[string]struct{}
}

// Container contains config state for a container. It should be Read Only. It should only be initialized via a
// constructor, and not directly.
type Container interface {
	AllowCPUBursting() bool
	AllowNetworkBursting() bool
	AppName() string
	AssignIPv6Address() bool
	BandwidthLimitMbps() *int64
	BatchPriority() *string
	Capabilities() *titus.ContainerInfo_Capabilities
	CombinedAppStackDetails() string
	ContainerInfo() (*titus.ContainerInfo, error)
	EfsConfigInfo() []*titus.ContainerInfo_EfsConfigInfo
	Env() map[string]string
	ElasticIPPool() *string
	ElasticIPs() *string
	FuseEnabled() bool
	GPUInfo() GPUContainer
	HostnameStyle() *string
	IamRole() *string
	ID() string
	ImageDigest() *string
	ImageName() *string
	ImageVersion() *string
	ImageTagForMetrics() map[string]string
	IPv4Address() *string
	IsSystemD() bool
	JobGroupDetail() string
	JobGroupStack() string
	JobGroupSequence() string
	JobID() *string
	KillWaitSeconds() *uint32
	KvmEnabled() bool
	Labels() map[string]string
	LogKeepLocalFileAfterUpload() bool
	LogStdioCheckInterval() *time.Duration
	LogUploadCheckInterval() *time.Duration
	LogUploaderConfig() *uploader.Config
	LogUploadRegexp() *regexp.Regexp
	LogUploadThresholdTime() *time.Duration
	MetatronCreds() *titus.ContainerInfo_MetatronCreds
	NormalizedENIIndex() *int
	OomScoreAdj() *int32
	Process() ([]string, []string)
	QualifiedImageName() string
	Resources() *Resources
	RequireIMDSToken() *string
	Runtime() string
	SeccompAgentEnabledForPerfSyscalls() bool
	SecurityGroupIDs() *[]string
	ServiceMeshEnabled() bool
	SetEnv(string, string)
	SetEnvs(env map[string]string)
	SetGPUInfo(GPUContainer)
	SetID(string)
	SetSystemD(bool)
	SetVPCAllocation(*vpcTypes.HybridAllocation)
	ShmSizeMiB() *uint32
	SidecarConfigs() (map[string]*SidecarContainerConfig, error)
	SignedAddressAllocationUUID() *string
	SortedEnvArray() []string
	SubnetIDs() *string
	TaskID() string
	TTYEnabled() bool
	UploadDir(string) string
	UseJumboFrames() bool
	VPCAllocation() *vpcTypes.HybridAllocation
	VPCAccountID() *string
}

func validateHostnameStyle(style string) error {
	if style == "" || style == ec2HostnameStyle {
		return nil
	}

	return fmt.Errorf("unknown hostname style: %s", style)
}

// ComputeHostname computes a hostname in the container using container ID or ec2 style
// depending on titusParameter.agent.hostnameStyle setting.  Return error if style is unrecognized.
func ComputeHostname(c Container) (string, error) {
	hostnameStyle := ""
	if style := c.HostnameStyle(); style != nil {
		hostnameStyle = strings.ToLower(*style)
	}

	if err := validateHostnameStyle(hostnameStyle); err != nil {
		return "", &InvalidConfigurationError{Reason: err}
	}

	switch hostnameStyle {
	case "":
		return strings.ToLower(c.TaskID()), nil
	case ec2HostnameStyle:
		ipAddr := c.IPv4Address()
		if ipAddr == nil {
			return "", &InvalidConfigurationError{Reason: errors.New("Unable to get container IP address")}
		}

		hostname := fmt.Sprintf("ip-%s", strings.Replace(*ipAddr, ".", "-", 3))
		return hostname, nil
	default:
		return "", &InvalidConfigurationError{Reason: fmt.Errorf("Unknown hostname style: %s", hostnameStyle)}
	}
}

// Generates a ContainerInfo config suitable for writing out to disk so the metadata proxy can use it
func ContainerConfig(c Container, startTime time.Time) (*titus.ContainerInfo, error) {
	launchTime := uint64(startTime.Unix())
	ti, err := c.ContainerInfo()
	if err != nil {
		return nil, err
	}
	containerHostname, err := ComputeHostname(c)
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
		tid := c.TaskID()
		ti.RunState.TaskId = &tid
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
	// See Container's Process() method for more details.
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

// ContainerTestArgs generates test arguments appropriate for passing to NewContainer()
func ContainerTestArgs() (string, *titus.ContainerInfo, *Resources, *config.Config, error) {
	cfg, err := config.GenerateConfiguration(nil)
	if err != nil {
		return "", nil, nil, nil, err
	}

	titusInfo := &titus.ContainerInfo{
		IamProfile: proto.String("arn:aws:iam::0:role/DefaultContainerRole"),
		NetworkConfigInfo: &titus.ContainerInfo_NetworkConfigInfo{
			EniLabel:  proto.String("1"),
			EniLablel: proto.String("1"), // deprecated, but protobuf marshaling raises an error if it's not present
		},
		PassthroughAttributes: map[string]string{},
	}
	resources := &Resources{
		Mem:     512,
		CPU:     2,
		GPU:     0,
		Disk:    10240,
		Network: 25600,
	}

	return "taskid", titusInfo, resources, cfg, nil
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
	IsRoutableIP     bool
	IPAddress        string
	ElasticIPAddress string
	EniIPAddress     string
	EniIPv6Address   string
	EniID            string
	ResourceID       string
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
	if n.ElasticIPAddress != "" {
		m["ElasticIPAddress"] = n.ElasticIPAddress
	}

	return m
}

// Details contains additional details about a container that are
// not returned by normal container start calls.
type Details struct {
	IPAddresses          map[string]string `json:"ipAddresses,omitempty"`
	NetworkConfiguration *NetworkConfigurationDetails
}

type ContainerRuntimeProvider func(ctx context.Context, c Container, startTime time.Time) (Runtime, error)

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
