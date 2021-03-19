package docker

func getContainerToolsBindMounts() []string {
	return []string{"/apps/titus-container-tools/:/titus/container-tools/:ro"}
}
