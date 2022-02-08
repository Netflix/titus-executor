//go:build !linux
// +build !linux

package netns

import (
	"context"
	"net"

	"github.com/Netflix/titus-executor/utils"
)

func (ns *NsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, utils.ErrorUnsupportedPlatform
}
