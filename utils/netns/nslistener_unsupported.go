//go:build !linux
// +build !linux

package netns

import (
	"net"

	"github.com/Netflix/titus-executor/utils"
)

func GetNsListener(netNsPath string, port int) (listener net.Listener, reterr error) {
	return nil, utils.ErrorUnsupportedPlatform
}
