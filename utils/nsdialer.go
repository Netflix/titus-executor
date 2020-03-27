package utils

import (
	"net"
	"os"
	"time"
)

type NsDialer struct {
	netNsPath string
	dialer    net.Dialer
}

func NewNsDialer(netNsPath string) (*NsDialer, error) {
	_, err := os.Stat(netNsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrorUnknownContainer
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
