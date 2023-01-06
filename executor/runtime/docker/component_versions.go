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
	componentVersions["tsa"] = getTSAVersion()
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
