package types

import "fmt"

import (
	"context"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/metatron"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	// The purpose of this is to tell gometalinter to keep vendoring this package
	_ "github.com/Netflix/titus-api-definitions/src/main/proto/netflix/titus"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
)

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
	Pid       int
	TaskID    string
	Env       map[string]string
	Labels    map[string]string
	Ports     []string
	TitusInfo *titus.ContainerInfo
	Resources *Resources

	// Metatron fields
	MetatronConfig *metatron.CredentialsConfig

	// cleanup callbacks that runtime implementations can register to do cleanup
	// after a launchGuard on the taskID has been lifted
	cleanup []CleanupFunc

	// VPC driver fields
	SecurityGroupIDs []string
	// Titus Index 1 = ENI index 0
	Allocation         vpcTypes.Allocation
	NormalizedENIIndex int
	BandwidthLimitMbps uint32

	// GPU devices
	GPUInfo GPUContainer

	AllocationCommand *exec.Cmd
	SetupCommand      *exec.Cmd

	Config config.Config
}

// QualifiedImageName appends the registry and version to the Image name
func (c *Container) QualifiedImageName() string {
	if c == nil {
		return ""
	}
	image := c.TitusInfo.GetImageName()
	baseRef := c.Config.DockerRegistry + "/" + image
	if digest := c.TitusInfo.GetImageDigest(); digest != "" {
		// digest has precedence
		return baseRef + "@" + digest
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

// GetEntrypointFromProto is a helper function to a parse the Protobuf entrypoint definition
// into a string array that the Docker client expects.
func (c *Container) GetEntrypointFromProto() ([]string, error) {
	var (
		cmd []string
		err error
	)
	switch {
	case c.TitusInfo.GetEntrypointStr() != "":
		// If entrypointStr is > 0 bytes then we're assuming that
		// this is the entrypoint to use, formatted as a single string
		envs := []string{}
		cmd, err = dockershellparser.ProcessWords(c.TitusInfo.GetEntrypointStr(), envs)
		if err != nil {
			return nil, err
		}
	case len(c.TitusInfo.GetEntrypointCmd()) > 0:
		cmd = append(cmd, c.TitusInfo.GetEntrypointCmd()...)
	default:
		// Neither of the entrypoints are set. Return an empty entrypoint
		// array indicating the entrypoint wasn't set.
	}

	return cmd, nil
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
	Prepare(containerCtx context.Context, c *Container, bindMounts []string) error
	// Start a container -- Returns an optional Log Directory if an external Logger is desired
	Start(containerCtx context.Context, c *Container) (string, *Details, error)
	// Kill a container
	Kill(*Container) error
	// Cleanup can be called to tear down resources after a container has been Killed
	Cleanup(*Container) error
	// Status of a Container
	Status(*Container) (Status, error)
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
