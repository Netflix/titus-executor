package docker

import (
	"errors"
	"fmt"

	"github.com/Netflix/titus-executor/executor/runtime/docker/seccomp"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types/container"
)

const (
	SYS_ADMIN = "SYS_ADMIN" // nolint: golint
)

func addAdditionalCapabilities(c *runtimeTypes.Container, hostCfg *container.HostConfig) map[string]struct{} {
	addedCapabilities := make(map[string]struct{})

	// Set any additional capabilities for this container
	if cap := c.TitusInfo.GetCapabilities(); cap != nil {
		for _, add := range cap.GetAdd() {
			addedCapabilities[add.String()] = struct{}{}
			hostCfg.CapAdd = append(hostCfg.CapAdd, add.String())
		}
		for _, drop := range cap.GetDrop() {
			hostCfg.CapDrop = append(hostCfg.CapDrop, drop.String())
		}
	}
	return addedCapabilities
}

func setupAdditionalCapabilities(c *runtimeTypes.Container, hostCfg *container.HostConfig) error {
	addedCapabilities := addAdditionalCapabilities(c, hostCfg)

	// Privileged containers automaticaly deactivate seccomp and friends, no need to do this
	fuseEnabled, err := c.GetFuseEnabled()

	if err != nil {
		return err
	}
	if fuseEnabled || c.TitusInfo.GetAllowNestedContainers() {
		if _, ok := addedCapabilities[SYS_ADMIN]; !ok {
			hostCfg.CapAdd = append(hostCfg.CapAdd, SYS_ADMIN)
		}
	}
	seccompProfile := "default.json"
	apparmorProfile := "docker_titus"

	if fuseEnabled {
		hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
			PathOnHost:        fuseDev,
			PathInContainer:   fuseDev,
			CgroupPermissions: "rmw",
		})
		apparmorProfile = "docker_fuse"
		seccompProfile = "fuse-container.json"

	}
	// We can do this here because nested containers can do everything fuse containers can
	if c.TitusInfo.GetAllowNestedContainers() {
		return errors.New("Nested containers no longer supported")
	}

	if c.IsSystemD {
		// Tell Tini to exec systemd so it's pid 1
		c.Env["TINI_HANDOFF"] = trueString
	}

	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "apparmor:"+apparmorProfile)
	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, fmt.Sprintf("seccomp=%s", string(seccomp.MustAsset(seccompProfile))))

	return nil
}
