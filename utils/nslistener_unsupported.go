// +build !linux

package utils

import "net"

func GetNsListener(netNsPath string, port int) (listener net.Listener, reterr error) {
	return nil, ErrorUnsupportedPlatform
}
