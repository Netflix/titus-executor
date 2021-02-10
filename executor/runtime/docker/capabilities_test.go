package docker

import (
	"testing"

	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	podCommon "github.com/Netflix/titus-kube-common/pod"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
)

func TestDefaultProfileContainerInfo(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := runtimeTypes.ContainerTestArgs()
	assert.NoError(t, err)
	c, err := runtimeTypes.NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Len(t, hostConfig.CapAdd, 0)
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_titus")
	assert.Len(t, hostConfig.SecurityOpt, 2)
}

func TestDefaultProfile(t *testing.T) {
	pod, conf, err := runtimeTypes.PodContainerTestArgs()
	assert.NoError(t, err)
	c, err := runtimeTypes.NewPodContainer(pod, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Len(t, hostConfig.CapAdd, 0)
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_titus")
	assert.Len(t, hostConfig.SecurityOpt, 2)
}

func TestFuseProfileContainerInfo(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := runtimeTypes.ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[runtimeTypes.FuseEnabledParam] = "true"
	c, err := runtimeTypes.NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Contains(t, hostConfig.CapAdd, "SYS_ADMIN")
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Len(t, hostConfig.SecurityOpt, 2)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_fuse")
}

func TestFuseProfile(t *testing.T) {
	pod, conf, err := runtimeTypes.PodContainerTestArgs()
	assert.NoError(t, err)
	pod.Annotations[podCommon.AnnotationKeyPodFuseEnabled] = "true"
	pod.Annotations[podCommon.AnnotationKeyPrefixAppArmor+"/"+pod.ObjectMeta.Name] = "docker_fuse"
	c, err := runtimeTypes.NewPodContainer(pod, *conf)
	assert.NoError(t, err)
	hostConfig := container.HostConfig{}

	// Using the full pod spec, the apparmor profile is specified in an annotation
	assert.NotNil(t, c.AppArmorProfile())
	assert.Equal(t, *c.AppArmorProfile(), "docker_fuse")
	assert.True(t, c.FuseEnabled())

	assert.NoError(t, setupAdditionalCapabilities(c, &hostConfig))

	assert.Contains(t, hostConfig.CapAdd, "SYS_ADMIN")
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Len(t, hostConfig.SecurityOpt, 2)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_fuse")
}
