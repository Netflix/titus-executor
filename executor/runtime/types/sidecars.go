package types

const (
	SidecarServiceAbMetrix    = "abmetrix"
	SidecarServiceLogViewer   = "logviewer"
	SidecarServiceMetatron    = "metatron"
	SidecarServiceServiceMesh = "servicemesh"
	SidecarServiceSshd        = "sshd"
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
}
