package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	executorDocker "github.com/Netflix/titus-executor/executor/runtime/docker"
	corev1 "k8s.io/api/core/v1"
)

const (
	lustreMountCmd = "/apps/titus-executor/bin/titus-mount-lustre"
)

func lustreRunner(ctx context.Context, command string, config MountConfig) error {
	switch command {
	case start:
		return lustreStart(ctx, config)
	case stop:
		return lustreStop(ctx, config)
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
}

func lustreStart(ctx context.Context, config MountConfig) error {
	pod := config.pod
	nameToMount := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		if v.FlexVolume != nil && v.FlexVolume.Driver == "LustreVolumeSource" && v.FlexVolume.Options != nil {
			nameToMount[v.Name] = v
		}
	}

	for _, container := range pod.Spec.Containers {
		for i := range container.VolumeMounts {
			vm := container.VolumeMounts[i]
			vol, ok := nameToMount[vm.Name]
			if !ok {
				continue
			}

			err := setupLustreMount(ctx, config.taskID, container.Name, &vol, &vm)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func setupLustreMount(parentCtx context.Context, taskID, cname string, vol *corev1.Volume, vm *corev1.VolumeMount) error {
	baseMountOptions := []string{"noatime,flock"}
	ctx, cancel := context.WithTimeout(parentCtx, mountTimeout)
	defer cancel()

	pidDir := executorDocker.GetTitusInitsPath(taskID, cname)
	cmd := exec.CommandContext(ctx, lustreMountCmd)
	flags := 0
	fsxFileSystemID := vol.FlexVolume.Options["fsxFileSystemId"]
	fsxMountName := vol.FlexVolume.Options["fsxMountName"]
	region := os.Getenv("EC2_REGION")
	lustreHost := fmt.Sprintf("%s.fsx.%s.amazonaws.com", fsxFileSystemID, region)
	lustreMountName := fsxMountName

	if vm.ReadOnly {
		flags = flags | MS_RDONLY
	}
	mountOptions := append(
		baseMountOptions,
		fmt.Sprintf("source=[%s]@tcp:%s", lustreHost, lustreMountName),
	)
	cmd.Env = []string{
		fmt.Sprintf("TITUS_PID1_DIR=%s", pidDir),
		fmt.Sprintf("MOUNT_TARGET=%s", filepath.Clean(vm.MountPath)),
		fmt.Sprintf("MOUNT_LUSTRE_HOSTNAME=%s", lustreHost),
		fmt.Sprintf("MOUNT_FLAGS=%d", flags),
		fmt.Sprintf("MOUNT_OPTIONS=%s", strings.Join(mountOptions, ",")),
	}

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Lustre Mount failure: %+v: %s", cmd, string(stdoutStderr))
	}

	return nil
}

func lustreStop(ctx context.Context, config MountConfig) error {
	return nil
}
