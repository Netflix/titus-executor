package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Netflix/titus-executor/executor/runtime/docker/seccomp"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types/container"
)

const (
	SYS_ADMIN = "SYS_ADMIN" // nolint: golint
	NET_ADMIN = "NET_ADMIN" // nolint: golint
)

func addAdditionalCapabilities(c runtimeTypes.Container, hostCfg *container.HostConfig) map[string]struct{} {
	addedCapabilities := make(map[string]struct{})

	// Set any additional capabilities for this container
	if cap := c.Capabilities(); cap != nil {
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

func setupAdditionalCapabilities(c runtimeTypes.Container, hostCfg *container.HostConfig) error {
	addedCapabilities := addAdditionalCapabilities(c, hostCfg)
	seccompProfile := "default.json"
	apparmorProfile := "docker_titus"

	if c.FuseEnabled() {
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

	if c.KvmEnabled() {
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

		value, exists := os.LookupEnv("ROOT_DEVICE_PATH")
		if exists {
			hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
				PathOnHost:        value,
				PathInContainer:   value,
				CgroupPermissions: "rmw",
			})
			c.SetEnv("ROOT_DEVICE_PATH", value)
		}

		hostCfg.Sysctls["net.ipv4.conf.all.accept_local"] = "1"
		hostCfg.Sysctls["net.ipv4.conf.all.route_localnet"] = "1"
		hostCfg.Sysctls["net.ipv4.conf.all.arp_ignore"] = "1"
	}

	if c.IsSystemD() {
		// Tell Tini to exec systemd so it's pid 1
		c.SetEnv("TINI_HANDOFF", trueString)
	}

	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "apparmor:"+apparmorProfile)
	asset := seccomp.MustAsset(seccompProfile)
	var buf bytes.Buffer
	err := json.Compact(&buf, asset)
	if err != nil {
		return fmt.Errorf("Could not JSON compact seccomp profile string: %w", err)
	}

	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, fmt.Sprintf("seccomp=%s", buf.String()))

	return nil
}
