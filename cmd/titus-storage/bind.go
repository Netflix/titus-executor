package main

import (
	"context"
	"fmt"
	"os"
	"path"

	executorDocker "github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/logger"
)

func mntSharedRunner(ctx context.Context, command string, config MountConfig) error {
	switch command {
	case "start":
		return mntSharedStart(ctx, config)
	case "stop":
		return mntSharedStop(ctx, config)
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
}

func mntSharedStart(ctx context.Context, config MountConfig) error {
	l := logger.GetLogger(ctx)
	path := getMntSharedPath(config.taskID)

	l.Info("Creating /mnt-shared on the host at " + path)
	err := createMntShared(path)
	if err != nil {
		return err
	}

	l.Info("Creating tmpfs at " + path)
	err = executorDocker.MountTmpfs(path, "5242880")
	if err != nil {
		err = fmt.Errorf("Unable to mount tmpfs at %s: %w", path, err)
		l.Error(err)
		return err
	}

	err = makeMountRShared(path)
	if err != nil {
		err = fmt.Errorf("Unable to make tmpfs at %s rshared: %w", path, err)
		l.Error(err)
		return err
	}

	for _, c := range config.pod.Spec.Containers {
		l.Infof("Mounting /mnt-shared into container %s", c.Name)
		pid1Dir := executorDocker.GetTitusInitsPath(config.taskID, c.Name)
		mc := MountCommand{
			source:     path,
			mountPoint: "/mnt-shared",
			pid1Dir:    pid1Dir,
		}
		err = mountBindInContainer(ctx, mc)
		if err != nil {
			return fmt.Errorf("Error mounting /mnt-shared in container %s: %w", c.Name, err)
		}
	}
	return err

}

func mntSharedStop(ctx context.Context, config MountConfig) error {
	l := logger.GetLogger(ctx)
	path := getMntSharedPath(config.taskID)
	l.Infof("Unmounting tmpfs at %s", path)
	err := executorDocker.UnmountLazily(path)
	if err != nil {
		l.Error(err)
	}
	return err
}

func createMntShared(path string) error {
	err := os.MkdirAll(path, os.FileMode(0755))
	if err != nil {
		return err
	}
	return os.Chmod(path, os.FileMode(0755))
}

func getMntSharedPath(taskID string) string {
	return path.Join("run", "titus-executor", "default__"+taskID, "mounts", "mnt-shared")
}
