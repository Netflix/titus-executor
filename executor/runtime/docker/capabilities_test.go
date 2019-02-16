package docker

import (
	"testing"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
)

func TestDefaultProfile(t *testing.T) {
	c := runtimeTypes.Container{
		TitusInfo: &titus.ContainerInfo{},
	}
	hostConfig := container.HostConfig{}

	assert.NoError(t, setupAdditionalCapabilities(&c, &hostConfig))

	assert.Len(t, hostConfig.CapAdd, 0)
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_titus")
	assert.Len(t, hostConfig.SecurityOpt, 2)
}

func TestFuseProfile(t *testing.T) {
	c := runtimeTypes.Container{
		TitusInfo: &titus.ContainerInfo{
			PassthroughAttributes: map[string]string{
				runtimeTypes.FuseEnabledParam: "true",
			},
		},
	}
	hostConfig := container.HostConfig{}

	assert.NoError(t, setupAdditionalCapabilities(&c, &hostConfig))

	assert.Contains(t, hostConfig.CapAdd, "SYS_ADMIN")
	assert.Len(t, hostConfig.CapDrop, 0)
	assert.Len(t, hostConfig.SecurityOpt, 2)
	assert.Contains(t, hostConfig.SecurityOpt, "apparmor:docker_fuse")
}
