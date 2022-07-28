//go:build !linux || noroot
// +build !linux noroot

package docker

import (
	"context"
	"net"

	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

func getPeerInfo(unixConn *net.UnixConn) (ucred, error) {
	return ucred{0, 0, 0}, nil
}

func setupScheduler(cred ucred) error {
	return nil
}

func hasProjectQuotasEnabled(rootDir string) bool {
	return false
}

func setupSystemServices(parentCtx context.Context, systemServices []*runtimeTypes.ServiceOpts, c runtimeTypes.Container, cfg config.Config) error {
	return nil
}

func (r *DockerRuntime) mountContainerProcPid1InTitusInits(parentCtx context.Context, c runtimeTypes.Container, cred ucred) error {
	return nil
}

func getOwnCgroup(subsystem string) (string, error) {
	return "", nil
}
func cleanupCgroups(cgroupPath string) error {
	return nil
}

func setCgroupOwnership(parentCtx context.Context, c runtimeTypes.Container, cred ucred) error {
	return nil
}

func setupOOMAdj(c runtimeTypes.Container, cred ucred) error {
	return nil
}

func stopSystemServices(ctx context.Context, c runtimeTypes.Container) error {
	return nil
}

func MountTmpfs(path string, size string) error {
	return nil
}

func UnmountLazily(path string) error {
	return nil
}
