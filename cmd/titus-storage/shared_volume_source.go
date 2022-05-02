package main

import (
	"context"
	"fmt"

	executorDocker "github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/logger"
	v1 "k8s.io/api/core/v1"
)

func sharedVolumeSourceRunner(ctx context.Context, command string, config MountConfig) error {
	switch command {
	case start:
		return sharedVolumeSourceRunnerStart(ctx, config)
	case stop:
		return nil
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
}

func sharedVolumeSourceRunnerStart(ctx context.Context, config MountConfig) error {
	l := logger.GetLogger(ctx)
	pod := config.pod
	volumes := pod.Spec.Volumes
	for _, c := range config.pod.Spec.Containers {
		for _, volumeMount := range c.VolumeMounts {
			v, ok := getVolumeByName(volumes, volumeMount.Name)
			if !ok {
				return fmt.Errorf("couldn't find the corresponding volume for volumeMount %+v", volumeMount)
			}
			if v.FlexVolume != nil && v.FlexVolume.Driver == "SharedContainerVolumeSource" && v.FlexVolume.Options != nil {
				sourcePath := v.FlexVolume.Options["sourcePath"]
				sourceContainer := v.FlexVolume.Options["sourceContainer"]
				destPath := volumeMount.MountPath
				destContainer := c.Name
				l.Infof("mounting shared volume %s:%s -> %s:%s", sourceContainer, sourcePath, destContainer, destPath)
				err := mountSharedVolumeSource(sourceContainer, sourcePath, destContainer, destPath, config.taskID)
				if err != nil {
					return fmt.Errorf("failed mount shared volume %+v: %w", volumeMount, err)
				}
			}
		}
	}
	return nil
}

func mountSharedVolumeSource(sourceContainer string, sourcePath string, destContainer string, destPath string, taskID string) error {
	srcPid1Dir := executorDocker.GetTitusInitsPath(taskID, sourceContainer)
	dstPid1Dir := executorDocker.GetTitusInitsPath(taskID, destContainer)
	return mountBindContainerToContainer(srcPid1Dir, sourcePath, dstPid1Dir, destPath)
}

func getVolumeByName(volumes []v1.Volume, name string) (v1.Volume, bool) {
	for _, v := range volumes {
		if v.Name == name {
			return v, true
		}
	}
	return v1.Volume{}, false
}
