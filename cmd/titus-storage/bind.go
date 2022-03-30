package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"syscall"

	"github.com/Netflix/titus-executor/logger"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
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
	l := logger.GetLogger(ctx)

	path := path.Join("/run/titus-executor/default__"+config.taskID, "/mounts/mnt-shared")

	l.Info("Creating /mnt/shared for " + path)
	err = createMntShared(path)
	if err != nil {
		return err
	}

	l.Info("Creating tmpfs for " + path)
	err = mountTmpfs(path)
	if err != nil {
		l.Error(err)
		return err
	}

	client, err := docker.NewClient("unix:///var/run/docker.sock", "1.26", nil, map[string]string{})
	l.Infof("%+v", config.pod.Status.ContainerStatuses)
	for _, cStatus := range config.pod.Status.ContainerStatuses {
		l.Infof("Mounting /mnt/shared into container %s cid %s", &cStatus.Name, &cStatus.ContainerID)
		cID := cStatus.ContainerID
		if cID == "" {
			cID = containerNameToCID(client, cStatus.Name)
			//return fmt.Errorf("No CID available for %s?", cStatus.Name)
		}
		pid1, err := cid2Pid1(ctx, client, cID)
		if err != nil {
			return fmt.Errorf("Error looking up pid1 for container %s: %w", cID, err)
		}
		pid1Dir := pid12Pid1Dir(pid1)
		mc := MountCommand{
			source:     path,
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

func createMntShared(path string) error {
	err := os.MkdirAll(path, os.FileMode(0755))
	if err != nil {
		return err
	}
	err = os.Chmod(path, os.FileMode(0755))
	if err != nil {
		return err
	}
	// TODO:
	// mount --make-rshared /run/titus-executor/default__c8ab3af7-2626-4ba2-8c05-1358810c052b/mounts/mnt-shared
	// touch  /run/titus-executor/default__c8ab3af7-2626-4ba2-8c05-1358810c052b/mounts/mnt-shared/this-is-mnt-shared
	return err
}

func mountTmpfs(path string) error {
	size := "134217728"
	var flags uintptr
	flags = syscall.MS_NOATIME
	flags |= syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID
	options := "size=" + size
	fmt.Printf("Running mount tmpfs on %s\n", path)
	err := syscall.Mount("none", path, "tmpfs", flags, options)
	fmt.Printf("error? %s\n", err)
	return os.NewSyscallError("mount", err)
}

func containerNameToCID(client *docker.Client, cName string) string {
	filter := filters.NewArgs()
	filter.Add("status", "running")
	filter.Add("name", cName)

	containers, err := client.ContainerList(context.TODO(), types.ContainerListOptions{Filters: filter, All: false})
	if err != nil {
		return fmt.Sprintf("Unable to get containers: %s", err)
	}
	return containers[0].ID
}
