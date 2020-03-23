// +build !linux

package api

import (
	"context"
	"net"
	"time"
)

type nsDialer struct {
	systemDialer net.Dialer
}

func (d *nsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Use the system dialer - doing a Setns() is only doable on Linux
	return d.systemDialer.DialContext(ctx, network, address)
}

func newDialer(containerID string) (*nsDialer, error) {
	return &nsDialer{
		systemDialer: net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		},
	}, nil
}
