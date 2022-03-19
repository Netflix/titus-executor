package main

import (
	"context"
	"fmt"
)

func mntSharedRunner(ctx context.Context, command string, config MountConfig) error {
	switch command {
	case "start":
		return mntSharedStart(ctx, config)
	case "stop":
		return nil
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
}

func mntSharedStart(ctx context.Context, config MountConfig) error {
	mc := MountCommand{
		// TODO: centralize this path logic
		source:     "/run/titus-executor/default__" + config.taskID + "/mounts/mnt-shared",
		mountPoint: "/mnt-shared",
		pid1Dir:    config.pid1Dir,
	}
	return mountBindInContainer(ctx, mc)
}
