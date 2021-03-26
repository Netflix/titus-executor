package types

const (
	SidecarServiceAbMetrix    = "abmetrix"
	SidecarServiceLogViewer   = "logviewer"
	SidecarServiceMetatron    = "metatron"
	SidecarServiceServiceMesh = "servicemesh"
	SidecarServiceSshd        = "sshd"
	SidecarServiceSpectatord  = "spectatord"
	SidecarServiceAtlasd      = "atlasd"
)

var sideCars = []SidecarContainerConfig{
	{
		ServiceName: SidecarServiceAbMetrix,
		Volumes: map[string]struct{}{
			"/titus/abmetrix": {},
		},
	},
	{
		ServiceName: SidecarServiceLogViewer,
		Volumes: map[string]struct{}{
			"/titus/adminlogs": {},
		},
	},
	{
		ServiceName: SidecarServiceMetatron,
		Volumes: map[string]struct{}{
			"/titus/metatron": {},
		},
	},
	{
		ServiceName: SidecarServiceSshd,
		Volumes: map[string]struct{}{
			"/titus/sshd": {},
		},
	},
	{
		ServiceName: SidecarServiceServiceMesh,
		Volumes: map[string]struct{}{
			"/titus/proxyd": {},
		},
	},
	{
		ServiceName: SidecarServiceSpectatord,
		Volumes: map[string]struct{}{
			"/titus/spectatord": {},
		},
	},
	{
		ServiceName: SidecarServiceAtlasd,
		Volumes: map[string]struct{}{
			"/titus/atlas-titus-agent": {},
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
