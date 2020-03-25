// +build !linux

package api

import (
	"net"
)

// Non-Linux OSes can't do a Setns(), so use the system dialer instead
type nsDialer = net.Dialer

func newDialer(containerID string) (*nsDialer, error) {
	var d nsDialer
	return &d, nil
}
