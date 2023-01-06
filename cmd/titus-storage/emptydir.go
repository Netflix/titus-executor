package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	executorDocker "github.com/Netflix/titus-executor/executor/runtime/docker"
	"github.com/Netflix/titus-executor/logger"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func emptyDirRunner(ctx context.Context, command string, config MountConfig) error {
	switch command {
	case start:
		return emptyDirStart(ctx, config)
	case stop:
		return emptyDirStop(ctx, config)
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
}

func emptyDirStart(ctx context.Context, config MountConfig) error {
	pod := config.pod
	nameToVolume := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		if v.EmptyDir != nil && v.EmptyDir.SizeLimit != nil && v.Name != "dev-shm" {
			nameToVolume[v.Name] = v
		}
	}

	for _, container := range pod.Spec.Containers {
		for i := range container.VolumeMounts {
			vm := container.VolumeMounts[i]
			vol, ok := nameToVolume[vm.Name]
			if !ok {
				continue
			}

			err := setupEmptyDirMount(ctx, config.taskID, container.Name, &vol, &vm)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func setupEmptyDirMount(parentCtx context.Context, taskID, cname string, vol *corev1.Volume, vm *corev1.VolumeMount) error {
	l := logger.GetLogger(parentCtx)
	l.Infof("Mounting an emptydir into container %s at %s", cname, vm.MountPath)
	ctx, cancel := context.WithTimeout(parentCtx, mountTimeout)
	defer cancel()

	runtimeDir := executorDocker.GetTitusTaskRunTimeDir(taskID)
	pid1Dir := executorDocker.GetTitusInitsPath(taskID, cname)
	hostPath := path.Join(runtimeDir, "/volumes/", vol.Name)

	err := setupRamdisk(ctx, hostPath, vol.EmptyDir.SizeLimit, pid1Dir)
	if err != nil {
		return fmt.Errorf("Error when setting up emptyDir %s: %w", hostPath, err)
	}
	mc := MountCommand{
		source:     hostPath,
		mountPoint: vm.MountPath,
		pid1Dir:    pid1Dir,
	}
	return mountBindInContainer(ctx, mc)

}

func setupRamdisk(ctx context.Context, hostPath string, sizeLimit *resource.Quantity, pid1Dir string) error {
	if _, err := os.Stat(hostPath); !os.IsNotExist(err) {
		// If the path already exists, then it may have been setup already.
		// No need to make the ramdisk twice
		return nil
	}
	err := os.MkdirAll(hostPath, 0755)
	if err != nil {
		return fmt.Errorf("Error when trying to create %s: %w", hostPath, err)
	}
	sizeMB := resource.NewScaledQuantity(sizeLimit.Value(), resource.Mega).ToDec().Value()
	err = createTmpfs(ctx, hostPath, sizeMB)
	if err != nil {
		return fmt.Errorf("Error when creating ramdisk: %w", err)
	}
	return nil
}

func emptyDirStop(ctx context.Context, config MountConfig) error {
	return nil
}

func createTmpfs(ctx context.Context, hostPath string, sizeMB int64) error {
	l := logger.GetLogger(ctx)
	sizeArg := "size=100%"
	if sizeMB != 0 {
		sizeArg = fmt.Sprintf("size=%dm", sizeMB)
	}
	args := []string{"-t", "tmpfs", "-o", sizeArg, "tmpfs", hostPath}
	cmd := exec.Command("/bin/mount", args...)
	l.Printf("Running %s to create ramdisk onto %s in the container", mountBindCommand, hostPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	l.Printf("%s %s", strings.Join(cmd.Env, " "), mountBindCommand)
	return cmd.Run()
}
