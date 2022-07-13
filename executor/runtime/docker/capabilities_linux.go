//go:build linux && !noroot
// +build linux,!noroot

package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	titusAPI "github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/executor/runtime/docker/seccomp"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types/container"
	"github.com/sirupsen/logrus"
)

const (
	SYS_ADMIN              = "SYS_ADMIN" // nolint: golint
	NET_ADMIN              = "NET_ADMIN" // nolint: golint
	defaultApparmorProfile = "docker_titus"
	defaultSeccompProfile  = "default.json"
)

func addAdditionalCapabilities(c runtimeTypes.Container, hostCfg *container.HostConfig) map[string]struct{} {
	addedCapabilities := make(map[string]struct{})

	// Set any additional capabilities for this container
	cp := c.Capabilities()
	if cp == nil {
		return addedCapabilities
	}

	for _, add := range cp.Add {
		addedCapabilities[string(add)] = struct{}{}
		hostCfg.CapAdd = append(hostCfg.CapAdd, string(add))
	}
	for _, drop := range cp.Drop {
		hostCfg.CapDrop = append(hostCfg.CapDrop, string(drop))
	}
	return addedCapabilities
}

func hasCapability(capabilities []titusAPI.ContainerCapability, toCheck titusAPI.ContainerCapability) bool {
	for _, c := range capabilities {
		if c == toCheck {
			return true
		}
	}

	return false
}

func setupAdditionalCapabilities(c runtimeTypes.Container, hostCfg *container.HostConfig, containerName string) error {
	addedCapabilities := addAdditionalCapabilities(c, hostCfg)
	seccompProfile := defaultSeccompProfile
	apparmorProfile := defaultApparmorProfile

	containerCapabilities, err := c.ContainerCapabilities(containerName)
	if err != nil {
		return err
	}

	if len(containerCapabilities) > 1 {
		return fmt.Errorf("multiple container capabilities (%v) are not supported", containerCapabilities)
	}

	if aProf := c.AppArmorProfile(); aProf != nil {
		apparmorProfile = *aProf
	}

	if hasCapability(containerCapabilities, titusAPI.ContainerCapability_ContainerCapabilityFUSE) {
		if _, ok := addedCapabilities[SYS_ADMIN]; !ok {
			hostCfg.CapAdd = append(hostCfg.CapAdd, SYS_ADMIN)
		}

		hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
			PathOnHost:        fuseDev,
			PathInContainer:   fuseDev,
			CgroupPermissions: "rmw",
		})

		if apparmorProfile == defaultApparmorProfile {
			apparmorProfile = "docker_fuse"
		}
		seccompProfile = "fuse-container.json"
	}

	if hasCapability(containerCapabilities, titusAPI.ContainerCapability_ContainerCapabilityImageBuilding) {
		if _, ok := addedCapabilities[SYS_ADMIN]; !ok {
			hostCfg.CapAdd = append(hostCfg.CapAdd, SYS_ADMIN)
		}

		seccompProfile = "image-building.json"
		apparmorProfile = "docker_image_building"
	}

	if c.SeccompAgentEnabledForPerfSyscalls() {
		if seccompProfile != defaultSeccompProfile {
			return fmt.Errorf("cannot mix container capabilities (allow perf and %s)", seccompProfile)
		}
		seccompProfile = "allow-perf-syscalls.json"
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

	logrus.Debug("using seccomp profile ", seccompProfile)
	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "apparmor:"+apparmorProfile)
	asset := seccomp.MustAsset(seccompProfile)
	var buf bytes.Buffer
	err = json.Compact(&buf, asset)
	if err != nil {
		return fmt.Errorf("Could not JSON compact seccomp profile string: %w", err)
	}

	hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, fmt.Sprintf("seccomp=%s", buf.String()))

	return nil
}
