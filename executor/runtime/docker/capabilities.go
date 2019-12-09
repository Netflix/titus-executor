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
	NET_ADMIN = "NET_ADMIN"
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
	if c.TitusInfo.GetAllowNestedContainers() {
		return errors.New("nested containers no longer supported")
	}

	fuseEnabled, err := c.GetFuseEnabled()
	if err != nil {
		return err
	}

	kvmEnabled, err := c.GetKvmEnabled()
	if err != nil {
		return err
	}

	addedCapabilities := addAdditionalCapabilities(c, hostCfg)
	seccompProfile := "default.json"
	apparmorProfile := "docker_titus"

	if fuseEnabled {
		if _, ok := addedCapabilities[SYS_ADMIN]; !ok {
			hostCfg.CapAdd = append(hostCfg.CapAdd, SYS_ADMIN)
		}

		hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
			PathOnHost:        fuseDev,
			PathInContainer:   fuseDev,
			CgroupPermissions: "rmw",
		})
		apparmorProfile = "docker_fuse"
		seccompProfile = "fuse-container.json"
	}

	if kvmEnabled {
		if _, ok := addedCapabilities[NET_ADMIN]; !ok {
			hostCfg.CapAdd = append(hostCfg.CapAdd, NET_ADMIN)
		}

		hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
			PathOnHost:        kvmDev,
			PathInContainer:   kvmDev,
			CgroupPermissions: "rmw",
		})
		hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
			PathOnHost:        tunDev,
			PathInContainer:   tunDev,
			CgroupPermissions: "rmw",
		})
	}

	if c.IsSystemD {
		// Tell Tini to exec systemd so it's pid 1
		c.Env["TINI_HANDOFF"] = trueString
	}

	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "apparmor:"+apparmorProfile)
	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, fmt.Sprintf("seccomp=%s", string(seccomp.MustAsset(seccompProfile))))

	return nil
}
