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
	mountBlockDeviceCommand = "/apps/titus-executor/bin/titus-mount-block-device"
)

type MountCommand struct {
	source     string
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
	l.Printf("Running %s to mount %s onto %s in the container", mountBlockDeviceCommand, mc.source, mc.mountPoint)
	cmd := exec.Command(mountBlockDeviceCommand)
	cmd.Env = []string{
		"TITUS_PID_1_DIR=" + mc.pid1Dir,
		"MOUNT_TARGET=" + mc.mountPoint,
		"MOUNT_OPTIONS=source=" + mc.source,
		"MOUNT_FLAGS=" + flags,
		"MOUNT_FSTYPE=" + mc.fstype,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	l.Printf("%s %s", strings.Join(cmd.Env, " "), mountBlockDeviceCommand)
	return cmd.Run()
}

// waitForDeviceToBeNotInUse polls once a second to see if a unix device
// file to see if it is "in use" aka mounted.
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
