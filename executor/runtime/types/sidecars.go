package types

import (
	"github.com/Netflix/titus-executor/config"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	SidecarTitusContainer       = "titus-container"
	SidecarServiceAbMetrix      = "abmetrix"
	SidecarServiceLogViewer     = "logviewer"
	SidecarServiceMetatron      = "metatron"
	SidecarServiceServiceMesh   = "servicemesh"
	SidecarServiceSshd          = "sshd"
	SidecarServiceSpectatord    = "spectatord"
	SidecarServiceAtlasd        = "atlasd"
	SidecarServiceAtlasAgent    = "atlas-agent"
	SidecarTitusStorage         = "titus-storage"
	SidecarSeccompAgent         = "seccomp-agent"
	SidecarServiceMetadataProxy = "metadata-proxy"
	SidecarContainerTools       = "container-tools"
)

var systemServices = []ServiceOpts{
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
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/spectatord": {},
		},
	},
	{
		ServiceName:  SidecarServiceAtlasd,
		UnitName:     "titus-sidecar-atlasd",
		EnabledCheck: shouldStartAtlasd,
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/atlas-titus-agent": {},
		},
	},
	{
		ServiceName:  SidecarServiceAtlasAgent,
		UnitName:     "titus-sidecar-atlas-titus-agent",
		EnabledCheck: shouldStartAtlasAgent,
		Required:     false,
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
		ServiceName: SidecarServiceMetadataProxy,
		UnitName:    "titus-sidecar-metadata-proxy",
		Required:    true,
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
		ServiceName:  SidecarSeccompAgent,
		UnitName:     "titus-sidecar-seccomp-agent",
		Required:     true,
		EnabledCheck: shouldStartTitusSeccompAgent,
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
}

func shouldStartMetatronSync(cfg *config.Config, c Container) bool {
	if cfg.MetatronEnabled && c.MetatronCreds() != nil {
		return true
	}

	return false
}

func shouldStartTitusSeccompAgent(cfg *config.Config, c Container) bool {
	return c.SeccompAgentEnabledForPerfSyscalls() || c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String()
}

func shouldStartServiceMesh(cfg *config.Config, c Container) bool {
	return c.ServiceMeshEnabled()
}

func shouldStartAbmetrix(cfg *config.Config, c Container) bool {
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
	enabled := cfg.ContainerSpectatord
	if !enabled {
		return false
	}

	if cfg.SpectatordServiceImage == "" {
		return false
	}
	return true
}

func shouldStartAtlasd(cfg *config.Config, c Container) bool {
	enabled := cfg.ContainerAtlasd
	if !enabled {
		return false
	}

	if cfg.AtlasdServiceImage == "" {
		return false
	}
	return true
}

// This starts the old version of the atlas titus agent, which we are migrating to a system service.
func shouldStartAtlasAgent(cfg *config.Config, c Container) bool {
	return !shouldStartAtlasd(cfg, c)
}

func shouldStartSSHD(cfg *config.Config, c Container) bool {
	return cfg.ContainerSSHD
}

func shouldStartLogViewer(cfg *config.Config, c Container) bool {
	return cfg.ContainerLogViewer
}

func shouldStartTitusStorage(cfg *config.Config, c Container) bool {
	// Currently titus-storage only supports EBS and /ephemeral storage
	// which is currently only available on GPU instance types.
	return c.EBSInfo().VolumeID != "" || c.Resources().GPU > 0
}

func shouldStartContainerTools(cfg *config.Config, c Container) bool {
	return cfg.ContainerToolsImage != ""
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
