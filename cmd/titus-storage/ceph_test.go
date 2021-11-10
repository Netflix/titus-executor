package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMountOptions(t *testing.T) {

	options := cephOptions(CephMountCommand{
		perms:        "RW",
		mountPoint:   "/m/p",
		monitorIP:    "1.2.3.4,5.6.7.8",
		cephFSPath:   "/cephfs",
		containerPID: "1",
		name:         "admin",
		secret:       "secret",
	})
	assert.Equal(t, "name=admin,secret=secret", options)

}
