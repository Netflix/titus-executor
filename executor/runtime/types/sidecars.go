package types

import "github.com/Netflix/titus-executor/config"

const (
	SidecarServiceAbMetrix    = "abmetrix"
	SidecarServiceLogViewer   = "logviewer"
	SidecarServiceMetatron    = "metatron"
	SidecarServiceServiceMesh = "servicemesh"
	SidecarServiceSshd        = "sshd"
	SidecarServiceSpectatord  = "spectatord"
	SidecarServiceAtlasd      = "atlasd"
	SidecarTitusStorage       = "titus-storage"
	SidecarSeccompAgent       = "seccomp-agent"
)

var sideCars = map[string]*ServiceOpts{
	"titus-container": {
		UnitName: "titus-container",
		Required: true,
		Target:   true,
	},
	SidecarServiceSpectatord: {
		UnitName:     "titus-sidecar-spectatord",
		EnabledCheck: shouldStartSpectatord,
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/spectatord": {},
		},
	},
	SidecarServiceAtlasd: {
		UnitName:     "titus-sidecar-atlasd",
		EnabledCheck: shouldStartAtlasd,
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/atlas-titus-agent": {},
		},
	},
	"titus-sidecar-atlas-titus-agent": {
		UnitName:     "titus-sidecar-atlas-titus-agent",
		EnabledCheck: shouldStartAtlasAgent,
		Required:     false,
	},
	SidecarServiceSshd: {
		UnitName:     "titus-sidecar-sshd",
		EnabledCheck: shouldStartSSHD,
		Required:     false,
		Volumes: map[string]struct{}{
			"/titus/sshd": {},
		},
	},
	"titus-sidecar-metadata-proxy": {
		UnitName: "titus-sidecar-metadata-proxy",
		Required: true,
	},
	SidecarServiceMetatron: {
		UnitName:     "titus-sidecar-metatron-sync",
		Required:     true,
		InitCommand:  "/titus/metatron/bin/titus-metatrond --init",
		EnabledCheck: shouldStartMetatronSync,
		Volumes: map[string]struct{}{
			"/titus/metatron": {},
		},
	},
	SidecarServiceLogViewer: {
		UnitName:     "titus-sidecar-logviewer",
		Required:     true,
		EnabledCheck: shouldStartLogViewer,
		Volumes: map[string]struct{}{
			"/titus/adminlogs": {},
		},
	},
	SidecarServiceServiceMesh: {
		UnitName:     "titus-sidecar-servicemesh",
		Required:     true,
		EnabledCheck: shouldStartServiceMesh,
		Volumes: map[string]struct{}{
			"/titus/proxyd": {},
		},
	},
	SidecarServiceAbMetrix: {
		UnitName:     "titus-sidecar-abmetrix",
		Required:     false,
		EnabledCheck: shouldStartAbmetrix,
		Volumes: map[string]struct{}{
			"/titus/abmetrix": {},
		},
	},
	SidecarSeccompAgent: {
		UnitName:     "titus-sidecar-seccomp-agent",
		Required:     true,
		EnabledCheck: shouldStartTitusSeccompAgent,
	},
	SidecarTitusStorage: {
		UnitName:     "titus-sidecar-storage",
		Required:     true,
		EnabledCheck: shouldStartTitusStorage,
	},
}

func shouldStartMetatronSync(cfg *config.Config, c Container) bool {
	if cfg.MetatronEnabled && c.MetatronCreds() != nil {
		return true
	}

	return false
}

func shouldStartTitusSeccompAgent(cfg *config.Config, c Container) bool {
	return c.SeccompAgentEnabledForPerfSyscalls() || c.SeccompAgentEnabledForNetSyscalls()
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
	return c.EBSInfo().VolumeID != ""
}
