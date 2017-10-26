package runtime

import (
	"context"
	"fmt"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor/dockershellparser"
)

// Status represent a containers state
type Status int

// Possible Container status
const (
	StatusUnknown = Status(iota)
	StatusRunning
	StatusFinished
	StatusFailed
)

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
	Start(containerCtx context.Context, c *Container) (string, error)
	// Kill a container
	Kill(*Container) error
	// Cleanup can be called to tear down resources after a container has been Killed
	Cleanup(*Container) error
	// Details that are not returned by Start
	Details(*Container) (*Details, error)
	// Status of a Container
	Status(*Container) (Status, error)
}

// Details contains additional details about a container that are
// not returned by normal container start calls.
type Details struct {
	IPAddresses          map[string]string `json:"ipAddresses,omitempty"`
	NetworkConfiguration *NetworkConfigurationDetails
}

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
	reason error
}

// Error returns a string describing an error
func (e *BadEntryPointError) Error() string {
	return fmt.Sprintf("Bad entry point : %s", e.reason)
}

// InvalidSecurityGroupError represents an error where the provided
// security group is not valid.
type InvalidSecurityGroupError struct {
	reason error
}

// Error returns a string describing an error
func (e *InvalidSecurityGroupError) Error() string {
	return fmt.Sprintf("Invalid security group : %s", e.reason)
}

// GetEntrypointFromProto is a helper function to a parse the Protobuf entrypoint definition
// into a string array that the Docker client expects.
func GetEntrypointFromProto(titusInfo *titus.ContainerInfo) ([]string, error) {
	var (
		cmd []string
		err error
	)
	switch {
	case titusInfo.GetEntrypointStr() != "":
		// If entrypointStr is > 0 bytes then we're assuming that
		// this is the entrypoint to use, formatted as a single string
		envs := []string{}
		cmd, err = dockershellparser.ProcessWords(titusInfo.GetEntrypointStr(), envs)
		if err != nil {
			return nil, err
		}
	case len(titusInfo.GetEntrypointCmd()) > 0:
		cmd = append(cmd, titusInfo.GetEntrypointCmd()...)
	default:
		// Neither of the entrypoints are set. Return an empty entrypoint
		// array indicating the entrypoint wasn't set.
	}

	return cmd, nil
}
