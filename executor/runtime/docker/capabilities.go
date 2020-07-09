package docker

import (
	"errors"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/executor/runtime/docker/seccomp"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types/container"
)

const (
	SYS_ADMIN = "SYS_ADMIN" // nolint: golint
)

var (
	errNestedContainers = errors.New("nested containers no longer supported")
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
		return errNestedContainers
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

		value, exists := os.LookupEnv("ROOT_DEVICE_PATH")
		if exists {
			hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
				PathOnHost:        value,
				PathInContainer:   value,
				CgroupPermissions: "rmw",
			})
			c.Env["ROOT_DEVICE_PATH"] = value
		}

		hostCfg.Sysctls["net.ipv4.conf.all.accept_local"] = "1"
		hostCfg.Sysctls["net.ipv4.conf.all.route_localnet"] = "1"
		hostCfg.Sysctls["net.ipv4.conf.all.arp_ignore"] = "1"
	}

	if c.IsSystemD {
		// Tell Tini to exec systemd so it's pid 1
		c.Env["TINI_HANDOFF"] = trueString
	}

	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "apparmor:"+apparmorProfile)
	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, fmt.Sprintf("seccomp=%s", string(seccomp.MustAsset(seccompProfile))))

	return nil
}
