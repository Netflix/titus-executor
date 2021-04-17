package main

import (
	"testing"

	k8sMount "k8s.io/utils/mount"

	"github.com/stretchr/testify/assert"
)

func getMockAllMounts() []k8sMount.MountPoint {
	return []k8sMount.MountPoint{
		{Device: "/dev/RootBlock", Type: "extRoot", Path: "/"},
		{Device: "/dev/EphemeralBlock", Type: "extEphem", Path: "/ephemeral"},
		{Device: "/dev/Something", Type: "extSome", Path: "/thing"},
	}
}

func TestGetUnderlyingBlockDeviceFor(t *testing.T) {
	mockAllMounts := getMockAllMounts()
	var actual string
	var err error

	actual, err = getUnderlyingBlockDeviceFor("/ephemeral/foo/bar", mockAllMounts)
	assert.Equal(t, actual, "/dev/EphemeralBlock")
	assert.Nil(t, err)

	actual, err = getUnderlyingBlockDeviceFor("/etc/passwd", mockAllMounts)
	assert.Equal(t, actual, "/dev/RootBlock")
	assert.Nil(t, err)

	actual, err = getUnderlyingBlockDeviceFor("/thing", mockAllMounts)
	assert.Equal(t, actual, "/dev/Something")
	assert.Nil(t, err)
}

func TestGetUnderlyingFSTypeFor(t *testing.T) {
	mockAllMounts := getMockAllMounts()
	var actual string
	var err error

	actual, err = getUnderlyingFSTypeFor("/dev/RootBlock", mockAllMounts)
	assert.Equal(t, actual, "extRoot")
	assert.Nil(t, err)

	actual, err = getUnderlyingFSTypeFor("/dev/EphemeralBlock", mockAllMounts)
	assert.Equal(t, actual, "extEphem")
	assert.Nil(t, err)

	actual, err = getUnderlyingFSTypeFor("/dev/DNE", mockAllMounts)
	assert.Equal(t, actual, "")
	assert.NotNil(t, err)
}
