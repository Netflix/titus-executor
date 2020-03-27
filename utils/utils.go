package utils

import (
	"errors"
)

const (
	TitusInits      = "/var/lib/titus-inits"
	CurrThreadNetNs = "/proc/thread-self/ns/net"
)

var (
	ErrorUnknownContainer    = errors.New("Unknown container")
	ErrorUnsupportedPlatform = errors.New("Unsupported platform")
)
