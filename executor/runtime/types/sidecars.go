package types

import (
	"github.com/Netflix/titus-executor/config"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	SidecarTitusContainer          = "titus-container"
	SidecarServiceAbMetrix         = "abmetrix"
	SidecarServiceLogViewer        = "logviewer"
	SidecarServiceMetatron         = "metatron"
	SidecarServiceServiceMesh      = "servicemesh"
	SidecarServiceSshd             = "sshd"
	SidecarServiceSpectatord       = "spectatord"
	SidecarServiceSystemDNS        = "systemdns"
	SidecarServiceTracingCollector = "tracing-collector"
	SidecarServiceAtlasTitusAgent  = "atlas-titus-agent"
	SidecarTitusStorage            = "titus-storage"
	SidecarSeccompAgent            = "seccomp-agent"
	SidecarServiceMetadataProxy    = "metadata-proxy"
	SidecarContainerTools          = "container-tools"
	SidecarTrafficSteering         = "traffic-steering"
)

var systemServices = []ServiceOpts{

	/*
	 * Titus sidecar seccomp agent must be in the beginning of the list because
	 * other sidecars may depend on it for IPv6 connectivity
	 */
	{
		ServiceName:  SidecarSeccompAgent,
		UnitName:     "titus-sidecar-seccomp-agent",
		Required:     true,
		EnabledCheck: shouldStartTitusSeccompAgent,
	},
	{
		ServiceName:  SidecarServiceSystemDNS,
		UnitName:     "titus-sidecar-systemdns",
		Required:     true,
		EnabledCheck: ShouldStartSystemDNS,
		Volumes: map[string]struct{}{
			"/titus/systemdns": {},
		},
	},
	{
		ServiceName: SidecarTitusContainer,
		UnitName:    "titus-container",
		Required:    true,
		Target:      true,
	},
	{
		ServiceName:  SidecarServiceSpectatord,
		UnitName:     "titus-sidecar-spectatord",
		EnabledCheck: shouldStartSpectatord,
		Required:     true,
		Volumes: map[string]struct{}{
			"/titus/spectatord": {},
		},
	},
	{
		ServiceName:  SidecarServiceTracingCollector,
		UnitName:     "titus-sidecar-tracing-collector",
		EnabledCheck: shouldStartTracingCollector,
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/tracing-collector": {},
		},
	},
	{
		ServiceName:  SidecarServiceAtlasTitusAgent,
		UnitName:     "titus-sidecar-atlas-titus-agent",
		EnabledCheck: shouldStartAtlasTitusAgent,
		Required:     true,
		Volumes: map[string]struct{}{
			"/titus/atlas-titus-agent": {},
		},
	},
	{
		ServiceName:  SidecarServiceSshd,
		UnitName:     "titus-sidecar-sshd",
		EnabledCheck: shouldStartSSHD,
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/sshd": {},
		},
	},
	{
		ServiceName:  SidecarServiceMetadataProxy,
		UnitName:     "titus-sidecar-metadata-proxy",
		Required:     true,
		EnabledCheck: shouldStartMetadataProxy,
	},
	{
		ServiceName:  SidecarServiceMetatron,
		UnitName:     "titus-sidecar-metatron-sync",
		Required:     true,
		InitCommand:  "/titus/metatron/bin/titus-metatrond --init",
		EnabledCheck: shouldStartMetatronSync,
		Volumes: map[string]struct{}{
			"/titus/metatron": {},
		},
	},
	{
		ServiceName:  SidecarServiceLogViewer,
		UnitName:     "titus-sidecar-logviewer",
		Required:     true,
		EnabledCheck: shouldStartLogViewer,
		Volumes: map[string]struct{}{
			"/titus/adminlogs": {},
		},
	},
	{
		ServiceName:  SidecarServiceServiceMesh,
		UnitName:     "titus-sidecar-servicemesh",
		Required:     true,
		EnabledCheck: shouldStartServiceMesh,
		Volumes: map[string]struct{}{
			"/titus/proxyd": {},
		},
	},
	{
		ServiceName:  SidecarServiceAbMetrix,
		UnitName:     "titus-sidecar-abmetrix",
		Required:     false,
		EnabledCheck: shouldStartAbmetrix,
		Volumes: map[string]struct{}{
			"/titus/abmetrix": {},
		},
	},
	{
		ServiceName:  SidecarTitusStorage,
		UnitName:     "titus-sidecar-storage",
		Required:     true,
		EnabledCheck: shouldStartTitusStorage,
	},
	{
		ServiceName:  SidecarContainerTools,
		UnitName:     "",
		Required:     false,
		EnabledCheck: shouldStartContainerTools,
		Volumes: map[string]struct{}{
			"/titus/container-tools": {},
		},
	},
	{
		ServiceName:  SidecarTrafficSteering,
		UnitName:     "titus-sidecar-traffic-steering",
		Required:     true,
		EnabledCheck: shouldStartTitusTrafficSteering,
	},
}

func shouldStartMetatronSync(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	if cfg.MetatronEnabled && c.MetatronCreds() != nil {
		return true
	}

	return false
}

func shouldStartTitusSeccompAgent(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	return c.SeccompAgentEnabledForPerfSyscalls() || c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String() || c.TrafficSteeringEnabled()
}

func ShouldStartSystemDNS(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	// don't start SystemDNS unless we're in IPv6-only mode
	if c.EffectiveNetworkMode() != titus.NetworkConfiguration_Ipv6Only.String() {
		return false
	}
	enabled := cfg.ContainerSystemDNS
	if !enabled {
		return false
	}
	if cfg.SystemDNSServiceImage == "" {
		return false
	}
	return true
}

func shouldStartServiceMesh(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	return c.ServiceMeshEnabled()
}

func shouldStartAbmetrix(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	enabled := cfg.ContainerAbmetrixEnabled
	if !enabled {
		return false
	}

	if cfg.AbmetrixServiceImage == "" {
		return false
	}
	return true

}

func shouldStartSpectatord(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	enabled := cfg.ContainerSpectatord
	if !enabled {
		return false
	}

	if cfg.SpectatordServiceImage == "" {
		return false
	}
	return true
}

func shouldStartTracingCollector(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	enabled := cfg.ContainerTracingCollector
	if !enabled {
		return false
	}

	if cfg.TracingCollectorServiceImage == "" {
		return false
	}
	return true
}

func shouldStartAtlasTitusAgent(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	enabled := cfg.ContainerAtlasTitusAgent
	if !enabled {
		return false
	}

	if cfg.AtlasTitusAgentServiceImage == "" {
		return false
	}
	return true
}

func shouldStartSSHD(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	return cfg.ContainerSSHD
}

func shouldStartLogViewer(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	return cfg.ContainerLogViewer
}

func shouldStartTitusStorage(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	// Currently titus-storage sets up NFS, EBS, and /mnt-shared storage
	// which is currently only available on multi-container workloads
	pod, podLock := c.Pod()
	defer podLock.Unlock()
	return len(c.NFSMounts()) > 0 || c.EBSInfo().VolumeID != "" || len(pod.Spec.Containers) > 1
}

func shouldStartContainerTools(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	return cfg.ContainerToolsImage != ""
}

func shouldStartTitusTrafficSteering(cfg *config.Config, c Container) bool {
	if cfg.InStandaloneMode {
		return false
	}
	return c.TrafficSteeringEnabled()
}

func shouldStartMetadataProxy(cfg *config.Config, c Container) bool {
	return !cfg.InStandaloneMode
}

// GetSidecarConfig is a helper to get a particular sidecar config out by name
// returns nil if you get the name wrong. Use the types Consts when possible.
func GetSidecarConfig(sidecars []*ServiceOpts, sidecarName string) *ServiceOpts {
	for _, s := range sidecars {
		if s.ServiceName == sidecarName {
			return s
		}
	}
	return nil
}
