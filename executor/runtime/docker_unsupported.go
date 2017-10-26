// +build !linux

package runtime

import (
	"context"
	"errors"
	"net"
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

func setupSystemPods(parentCtx context.Context, c *Container, cred ucred) error {
	return nil
}
