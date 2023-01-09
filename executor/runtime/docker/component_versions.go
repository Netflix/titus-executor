package docker

import (
	"fmt"
	"os"
	"strings"

	"github.com/Netflix/titus-executor/executor"
)

func (r *DockerRuntime) getComponentVersions() map[string]string {
	componentVersions := map[string]string{}
	componentVersions["kernel-version"] = getKernelVersion()
	componentVersions["titus-executor"] = executor.TitusExecutorVersion
	componentVersions["tss-tsa"] = getTSAVersion()
	for k, v := range r.getTitusSystemServiceVersions() {
		componentVersions["tss-"+k] = v
	}
	return componentVersions
}

func getKernelVersion() string {
	kernelVersionRaw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return fmt.Sprintf("problem reading kernel version: %v", err)
	}
	return strings.TrimSpace(string(kernelVersionRaw))
}

func getTSAVersion() string {
	tsaVersionRaw, err := os.ReadFile("/apps/tsa/version")
	if err != nil {
		return fmt.Sprintf("problem reading tsa version: %v", err)
	}
	return strings.TrimSpace(string(tsaVersionRaw))
}

// getTitusSystemServiceVersions inspects the Titus System Service versions strings.
// If they are set (by the function that pulls the image), then we can report them back
func (r *DockerRuntime) getTitusSystemServiceVersions() map[string]string {
	systemServiceVersions := map[string]string{}
	for _, systemService := range r.systemServices {
		if systemService.Version != "" {
			systemServiceVersions[systemService.ServiceName] = systemService.Version
		}
	}
	return systemServiceVersions
}
