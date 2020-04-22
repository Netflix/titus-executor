package netns

import (
	"net"
	"os"
	"time"

	"github.com/Netflix/titus-executor/utils"
)

type NsDialer struct {
	netNsPath string
	dialer    net.Dialer
}

func NewNsDialer(netNsPath string) (*NsDialer, error) {
	_, err := os.Stat(netNsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, utils.ErrorUnknownContainer
		}

		return nil, err
	}

	return &NsDialer{
		netNsPath: netNsPath,
		dialer: net.Dialer{
			Timeout:       30 * time.Second,
			KeepAlive:     30 * time.Second,
			FallbackDelay: -1, // Disable IPv4 fallback
		},
	}, nil
}
