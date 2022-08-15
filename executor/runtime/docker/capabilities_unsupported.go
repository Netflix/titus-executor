//go:build !linux || noroot
// +build !linux noroot

package docker

import (
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types/container"
)

func setupAdditionalCapabilities(c runtimeTypes.Container, hostCfg *container.HostConfig, containerName string) error {
	return nil
}
