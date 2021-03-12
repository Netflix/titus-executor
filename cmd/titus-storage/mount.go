package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/logger"
)

const (
	mountCommand = "/apps/titus-executor/bin/titus-mount-block-device"
)

func calculateFlags(mountPerm string) (string, error) {
	if mountPerm == "RW" {
		return "0", nil
	} else if mountPerm == "RO" {
		return "1", nil
	}
	return "", fmt.Errorf("error parsing the mount permissions: '%s', needs to be only RW/RO", mountPerm)
}

func mountIt(ctx context.Context, dev string, fstype string, mountPoint string, mountPerm string, pid1Dir string) error {
	l := logger.GetLogger(ctx)
	flags, err := calculateFlags(mountPerm)
	if err != nil {
		return err
	}
	if pid1Dir == "" {
		return fmt.Errorf("env var TITUS_PID_1_DIR is not set, unable to mount")
	}
	l.Printf("Running %s to mount %s onto %s in the container", mountCommand, dev, mountPoint)
	cmd := exec.Command(mountCommand)
	cmd.Env = []string{
		"TITUS_PID_1_DIR=" + pid1Dir,
		"MOUNT_TARGET=" + mountPoint,
		"MOUNT_OPTIONS=source=" + dev,
		"MOUNT_FLAGS=" + flags,
		"MOUNT_FSTYPE=" + fstype,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	l.Printf("%s %s", strings.Join(cmd.Env, " "), mountCommand)
	return cmd.Run()
}

func mkfsIfNeeded(dev string, fstype string) error {
	// TODO: Not currently supported
	return nil
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
