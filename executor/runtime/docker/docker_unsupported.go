// +build !linux

package docker

import (
	"context"
	"errors"
	"net"

	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

var (
	errUnsupported = errors.New("Unsupported on current platform")
)

func getPeerInfo(unixConn *net.UnixConn) (ucred, error) {
	return ucred{0, 0, 0}, errUnsupported
}

func setupScheduler(cred ucred) error {
	return errUnsupported
}

func hasProjectQuotasEnabled(rootDir string) bool {
	return false
}

func setupSystemServices(parentCtx context.Context, c *runtimeTypes.Container, cfg config.Config, cred ucred) error {
	return nil
}

func mountContainerProcPid1InTitusInits(parentCtx context.Context, c *runtimeTypes.Container, cred ucred) error {
	return nil
}

func getOwnCgroup(subsystem string) (string, error) {
	return "", errUnsupported
}
func cleanupCgroups(cgroupPath string) error {
	return errUnsupported
}

func setCgroupOwnership(parentCtx context.Context, c *runtimeTypes.Container, cred ucred) error {
	return errUnsupported
}

func setupOOMAdj(c *runtimeTypes.Container, cred ucred) error {
	return errUnsupported
}
