package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/logger"
	k8sMount "k8s.io/utils/mount"
)

const (
	mountBlockDeviceCommand = "/apps/titus-executor/bin/titus-mount-block-device"
	mountBindCommand        = "/apps/titus-executor/bin/titus-mount-bind"
)

type MountCommand struct {
	device     string
	perms      string
	pid1Dir    string
	mountPoint string
	fstype     string
}

func calculateFlags(mountPerm string) (string, error) {
	if mountPerm == "RW" {
		return "0", nil
	} else if mountPerm == "RO" {
		return "1", nil
	}
	return "", fmt.Errorf("error parsing the mount permissions: '%s', needs to be only RW/RO", mountPerm)
}

func mountBlockDeviceInContainer(ctx context.Context, mc MountCommand) error {
	l := logger.GetLogger(ctx)
	flags, err := calculateFlags(mc.perms)
	if err != nil {
		return err
	}
	if mc.pid1Dir == "" {
		return fmt.Errorf("env var TITUS_PID_1_DIR is not set, unable to mount")
	}
	l.Printf("Running %s to mount %s onto %s in the container", mountBlockDeviceCommand, mc.device, mc.mountPoint)
	cmd := exec.Command(mountBlockDeviceCommand)
	cmd.Env = []string{
		"TITUS_PID_1_DIR=" + mc.pid1Dir,
		"MOUNT_TARGET=" + mc.mountPoint,
		"MOUNT_OPTIONS=source=" + mc.device,
		"MOUNT_FLAGS=" + flags,
		"MOUNT_FSTYPE=" + mc.fstype,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	l.Printf("%s %s", strings.Join(cmd.Env, " "), mountBlockDeviceCommand)
	return cmd.Run()
}

func bindMountInContainer(ctx context.Context, mc MountCommand) error {
	l := logger.GetLogger(ctx)
	if mc.pid1Dir == "" {
		return fmt.Errorf("env var TITUS_PID_1_DIR is not set, unable to mount")
	}
	flags, err := calculateFlags(mc.perms)
	if err != nil {
		return err
	}
	l.Printf("Running %s to mount %s onto %s in the container", mountBindCommand, mc.device, mc.mountPoint)
	allMounts, err := listProcMounts()
	if err != nil {
		return err
	}
	absSource, err := filepath.Abs(mc.device)
	if err != nil {
		return err
	}
	blockDevice, err := getUnderlyingBlockDeviceFor(absSource, allMounts)
	if err != nil {
		return err
	}
	blockDeviceFSType, err := getUnderlyingFSTypeFor(blockDevice, allMounts)
	if err != nil {
		return err
	}

	cmd := exec.Command(mountBindCommand)
	cmd.Env = []string{
		"TITUS_PID_1_DIR=" + mc.pid1Dir,
		"MOUNT_TARGET=" + mc.mountPoint,
		"MOUNT_HOST_PATH=" + mc.device,
		"MOUNT_FLAGS=" + flags,
		"MOUNT_HOST_BLOCK_DEVICE=" + blockDevice,
		"MOUNT_HOST_FSTYPE=" + blockDeviceFSType,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	l.Printf("%s %s", strings.Join(cmd.Env, " "), mountBindCommand)
	return cmd.Run()
}

// Parses a source like /ephemeral/foo/bar, and givent input allMounts,
// scans the mounts to find the block device that is backing the most specific mount,
// often will be something like /ephemeral/, and whatever block device is behind that
func getUnderlyingBlockDeviceFor(source string, allMounts []k8sMount.MountPoint) (string, error) {
	sourceParts := strings.Split(source, "/")
	for i := len(sourceParts); i >= 0; i-- {
		prefix := "/" + path.Join(sourceParts[:i]...)
		device := getUnderlyingBlockDeviceForMountPath(prefix, allMounts)
		if device != "" {
			return device, nil
		}
	}
	// This should never really happen, as the root block device
	// will always represent the lowest level block device holding
	// a path
	return "", fmt.Errorf("Could not find block device backing %s", source)
}

func getUnderlyingBlockDeviceForMountPath(path string, allMounts []k8sMount.MountPoint) string {
	for _, m := range allMounts {
		if m.Path == path {
			return m.Device
		}
	}
	return ""
}

func getUnderlyingFSTypeFor(device string, allMounts []k8sMount.MountPoint) (string, error) {
	for _, m := range allMounts {
		if m.Device == device {
			return m.Type, nil
		}
	}
	return "", fmt.Errorf("Could not determine filesystem for %s", device)
}

func waitForDeviceToBeNotInUse(device string, timeout int) error {
	for attempts := 0; attempts < timeout; attempts++ {
		inUse, err := deviceIsInUse(device)
		if err != nil {
			return err
		}
		if !inUse {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Waited %d seconds for %s to not be in use, but it still is", timeout, device)
}

func deviceIsInUse(device string) (bool, error) {
	fd, err := os.OpenFile(device, os.O_EXCL, 0644)
	if err == nil {
		fd.Close()
		return false, nil
	} else if strings.Contains(err.Error(), "device or resource busy") {
		return true, nil
	} else {
		return true, fmt.Errorf("Got unexpected error when trying to determine if %s was open: %s", device, err)
	}
}
