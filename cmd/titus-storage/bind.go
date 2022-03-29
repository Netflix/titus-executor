package main

import (
	"context"
	"fmt"
	"path"
	"strconv"

	docker "github.com/docker/docker/client"
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
	var err error

	client, err := docker.NewClient("unix:///var/run/docker.sock", "1.26", nil, map[string]string{})
	for _, cStatus := range config.pod.Status.ContainerStatuses {
		cID := cStatus.ContainerID
		pid1, err := cid2Pid1(ctx, client, cID)
		if err != nil {
			return fmt.Errorf("Error looking up pid1 for container %s: %w", cID, err)
		}
		pid1Dir := pid12Pid1Dir(pid1)
		mc := MountCommand{
			// TODO: centralize this path logic
			source:     "/run/titus-executor/default__" + config.taskID + "/mounts/mnt-shared",
			mountPoint: "/mnt-shared",
			pid1Dir:    pid1Dir,
		}
		err = mountBindInContainer(ctx, mc)
		if err != nil {
			return fmt.Errorf("Error mounting /mnt/shared in container %s: %w", cID, err)
		}
	}
	return err

}

func cid2Pid1(ctx context.Context, client *docker.Client, cID string) (int, error) {
	inspect, err := client.ContainerInspect(ctx, cID)
	if err != nil {
		return 0, err
	}
	containerPID := inspect.State.Pid
	return containerPID, nil
}

func pid12Pid1Dir(pid1 int) string {
	pid1Str := strconv.Itoa(pid1)
	return path.Join("/proc", pid1Str)
}
