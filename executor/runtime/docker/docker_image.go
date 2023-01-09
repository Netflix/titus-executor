package docker

import (
	"strings"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/api/types"
)

// cleanContainerVersion tries to provide the most human-friendly version string we can get for
// a particular image, given a version inspect.
// It goes from most human-friendly to least (sha)
func cleanContainerVersion(i *types.ImageInspect) string {
	if i == nil {
		return ""
	}
	tag := getImageTagFromInspect(i)
	if tag != "" {
		return tag
	}
	buildLabel := getBuildLabelFromInspect(i)
	if buildLabel != "" {
		return buildLabel
	}
	return getImageShaFromInspect(i)
}

func getImageTagFromInspect(i *types.ImageInspect) string {
	if i.RepoTags == nil {
		return ""
	}
	if len(i.RepoTags) < 1 {
		return ""
	}
	return i.RepoTags[0]
}

func getBuildLabelFromInspect(i *types.ImageInspect) string {
	if i.Config == nil {
		return ""
	}
	if i.Config.Labels == nil {
		return ""
	}
	nameLabel, ok := i.Config.Labels["image-name"]
	if ok {
		versionLabel, ok := i.Config.Labels["image-version"]
		if ok {
			return "image:" + fullImageNameToShortName(nameLabel) + " build:" + versionLabel
		}
	}
	return ""
}

func getImageShaFromInspect(i *types.ImageInspect) string {
	if i.RepoDigests == nil {
		return ""
	}
	if len(i.RepoDigests) < 1 {
		return ""
	}
	name := fullImageNameToShortName(i.RepoDigests[0])
	splitDigest := strings.Split(i.RepoDigests[0], "@")
	if len(splitDigest) < 2 {
		return i.RepoDigests[0]
	}
	shortDigest := splitDigest[1]
	return "image:" + name + " digest:" + shortDigest
}

func fullImageNameToShortName(i string) string {
	ref, err := reference.ParseNamed(i)
	if err != nil {
		return i
	}
	return reference.Path(ref)
}
