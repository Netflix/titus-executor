package docker

import (
	"sync"
	"testing"

	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
)

const (
	True = "true"
)

func TestDefaultProfile(t *testing.T) {
	pod, conf, err := runtimeTypes.PodContainerTestArgs()
	assert.NoError(t, err)
	c, err := runtimeTypes.NewPodContainer(pod, &sync.Mutex{}, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Len(t, hostConfig.CapAdd, 0)
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_titus")
	assert.Len(t, hostConfig.SecurityOpt, 2)
}

func TestFuseProfile(t *testing.T) {
	pod, conf, err := runtimeTypes.PodContainerTestArgs()
	assert.NoError(t, err)
	pod.Annotations[podCommon.AnnotationKeyPodFuseEnabled] = True
	c, err := runtimeTypes.NewPodContainer(pod, &sync.Mutex{}, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	assert.True(t, c.FuseEnabled())
	assert.Nil(t, c.AppArmorProfile())

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Contains(t, hostConfig.CapAdd, "SYS_ADMIN")
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Len(t, hostConfig.SecurityOpt, 2)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_fuse")
}

func TestOverrideFuseProfile(t *testing.T) {
	pod, conf, err := runtimeTypes.PodContainerTestArgs()
	assert.NoError(t, err)
	// Using the full pod spec, the apparmor profile is specified in an annotation
	pod.Annotations[podCommon.AnnotationKeyPrefixAppArmor+"/"+runtimeTypes.MainContainerName] = "docker_foo"
	pod.Annotations[podCommon.AnnotationKeyPodFuseEnabled] = True
	c, err := runtimeTypes.NewPodContainer(pod, &sync.Mutex{}, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	assert.True(t, c.FuseEnabled())
	assert.NotNil(t, c.AppArmorProfile())
	assert.Equal(t, *c.AppArmorProfile(), "docker_foo")

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Contains(t, hostConfig.CapAdd, "SYS_ADMIN")
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Len(t, hostConfig.SecurityOpt, 2)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_foo")
}
