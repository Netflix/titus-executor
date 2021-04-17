package main

import (
	"context"
	"fmt"
	"os"
	"path"

	"github.com/Netflix/titus-executor/logger"
)

const (
	ephemeralStorageRoot = "/ephemeral"
	mountPathInContainer = "/ephemeral"
)

func ephemeralStorageIsAvailable() bool {
	_, err := os.Stat(ephemeralStorageRoot)
	return err == nil
}

func ephemeralStorageRunner(ctx context.Context, command string, config MountConfig) error {
	l := logger.GetLogger(ctx)
	var err error
	switch command {
	case "start":
		err = ephemeralStorageStart(ctx, config)
		if err != nil {
			l.Error("Failed to start. Running ephemeral storage stop as we wont get a stop command later on TASK_LOST")
			_ = ephemeralStorageStop(ctx, config)
		}
		return err
	case "stop":
		err = ephemeralStorageStop(ctx, config)
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
	if err != nil {
		return fmt.Errorf("Unable to run command %q: %w", command, err)
	}
	return nil
}

func ephemeralStorageStart(ctx context.Context, config MountConfig) error {
	l := logger.GetLogger(ctx)
	taskEphemeralStorageDir := getTaskEphemeralStorageDir(config.taskID)
	err := os.MkdirAll(taskEphemeralStorageDir, os.FileMode(0777))
	if err != nil {
		return fmt.Errorf("Couldn't create directory %s for ephemeral storage: %w", taskEphemeralStorageDir, err)
	}
	// MkdirAll isn't guaranteed to actually chmod for you, so you must
	// followup with your own chmod
	err = os.Chmod(taskEphemeralStorageDir, 0777)
	if err != nil {
		return fmt.Errorf("Couldn't chmod directory %s for ephemeral storage: %w", taskEphemeralStorageDir, err)
	}
	mc := MountCommand{
		device:     taskEphemeralStorageDir,
		mountPoint: mountPathInContainer,
		perms:      "RW",
		pid1Dir:    config.pid1Dir,
	}
	err = bindMountInContainer(ctx, mc)
	if err != nil {
		return err
	}
	l.Infof("Mounted ephemeral storage %s into %s in the container", taskEphemeralStorageDir, mountPathInContainer)
	return nil
}

func ephemeralStorageStop(ctx context.Context, config MountConfig) error {
	l := logger.GetLogger(ctx)
	taskEphemeralStorageDir := getTaskEphemeralStorageDir(config.taskID)
	l.Infof("Cleaning up ephemeral storage %s", taskEphemeralStorageDir)
	return os.RemoveAll(taskEphemeralStorageDir)
}

func getTaskEphemeralStorageDir(taskID string) string {
	return path.Join(ephemeralStorageRoot, "titus-task-storage", taskID)
}
