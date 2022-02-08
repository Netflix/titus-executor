package types

import (
	"testing"

	// nolint: staticcheck
	"github.com/stretchr/testify/assert"
)

func TestComputeNetflixIPv6Hostname(t *testing.T) {
	ip := "2001:db8::2:1"
	expected := "ip-2001-db8--2-1.node.netflix.net"
	actual := computeNetflixIPv6Hostname(ip)
	assert.Equal(t, expected, actual)
}
