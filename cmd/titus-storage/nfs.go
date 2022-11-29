package main

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	executorDocker "github.com/Netflix/titus-executor/executor/runtime/docker"
	corev1 "k8s.io/api/core/v1"
)

const (
	nfsMountCmd  = "/apps/titus-executor/bin/titus-mount-nfs"
	mountTimeout = 10 * time.Second
	// MS_RDONLY indicates that mount is read-only
	MS_RDONLY = 1 // nolint: golint
)

// setupNFSMount calls out to the titus-mount-nfs command to set up a single
// EFS mount.
func setupNFSMount(parentCtx context.Context, taskID, cname string, vol *corev1.Volume, vm *corev1.VolumeMount) error {
	baseMountOptions := []string{"vers=4.1,rsize=1048576,wsize=1048576,timeo=600,retrans=2"}
	ctx, cancel := context.WithTimeout(parentCtx, mountTimeout)
	defer cancel()

	pidDir := executorDocker.GetTitusInitsPath(taskID, cname)
	cmd := exec.CommandContext(ctx, nfsMountCmd)
	flags := 0

	if vm.ReadOnly {
		flags = flags | MS_RDONLY
	}
	mountOptions := append(
		baseMountOptions,
		fmt.Sprintf("fsc=%s", taskID),
		fmt.Sprintf("source=[%s]:%s", vol.NFS.Server, filepath.Clean(vol.NFS.Path)),
	)
	cmd.Env = []string{
		fmt.Sprintf("TITUS_PID1_DIR=%s", pidDir),
		fmt.Sprintf("MOUNT_TARGET=%s", filepath.Clean(vm.MountPath)),
		fmt.Sprintf("MOUNT_NFS_HOSTNAME=%s", vol.NFS.Server),
		fmt.Sprintf("MOUNT_FLAGS=%d", flags),
		fmt.Sprintf("MOUNT_OPTIONS=%s", strings.Join(mountOptions, ",")),
	}

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Mount failure: %+v: %s (%w)", cmd, string(stdoutStderr), err)
	}

	return nil
}

// setupNFSMounts sets up all of the mounts across all containers for the given pod.
func setupNFSMounts(parentCtx context.Context, taskID string, pod *corev1.Pod) error {
	nameToMount := map[string]corev1.Volume{}

	for _, vol := range pod.Spec.Volumes {
		if vol.VolumeSource.NFS == nil {
			continue
		}
		nameToMount[vol.Name] = vol
	}

	for _, container := range pod.Spec.Containers {
		for i := range container.VolumeMounts {
			vm := container.VolumeMounts[i]
			vol, ok := nameToMount[vm.Name]
			if !ok {
				continue
			}

			err := setupNFSMount(parentCtx, taskID, container.Name, &vol, &vm)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
