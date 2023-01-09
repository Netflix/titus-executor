package docker

import (
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/stretchr/testify/assert"
)

func Test_fullImageNameToShortName(t *testing.T) {
	actual := fullImageNameToShortName("registry.us-east-1.streamingtest.titus.netflix.net:7002/baseos/nflx-adminlogs@sha256:e4493a553868687b0cee2f7783c6eeb9c260374a4b5a137c52b7c53961433afe")
	expected := "baseos/nflx-adminlogs"
	assert.Equal(t, expected, actual)
}

func Test_cleanContainerVersionHandlesDigests(t *testing.T) {
	i := &types.ImageInspect{
		RepoDigests: []string{"registry.us-east-1.streamingtest.titus.netflix.net:7002/baseos/nflx-adminlogs@sha256:e4493a553868687b0cee2f7783c6eeb9c260374a4b5a137c52b7c53961433afe"},
	}
	actual := cleanContainerVersion(i)
	expected := "image:baseos/nflx-adminlogs digest:sha256:e4493a553868687b0cee2f7783c6eeb9c260374a4b5a137c52b7c53961433afe"
	assert.Equal(t, expected, actual)
}

func Test_cleanContainerVersionHandlesLabels(t *testing.T) {
	i := &types.ImageInspect{
		RepoDigests: []string{"registry.us-east-1.streamingtest.titus.netflix.net:7002/baseos/nflx-adminlogs@sha256:e4493a553868687b0cee2f7783c6eeb9c260374a4b5a137c52b7c53961433afe"},
		Config: &container.Config{
			Labels: map[string]string{
				"image-version": "master.last.good-h427.308e880",
				"image-name":    "dockerregistry.test.netflix.net:7002/baseos/nflx-adminlogs:pre-release",
			},
		},
	}
	actual := cleanContainerVersion(i)
	expected := "image:baseos/nflx-adminlogs build:master.last.good-h427.308e880"
	assert.Equal(t, expected, actual)
}
