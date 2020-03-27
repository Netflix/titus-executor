// +build !linux

package utils

import (
	"context"
	"net"
)

func (ns *NsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, ErrorUnsupportedPlatform
}
