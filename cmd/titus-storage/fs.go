package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Netflix/titus-executor/logger"
)

func isMkfsNeeded(ctx context.Context, device string, fstype string) (bool, error) {
	l := logger.GetLogger(ctx)
	existingFormat, err := getDiskFormat(ctx, device)
	if err != nil {
		return false, err
	}
	if existingFormat == "" {
		return true, nil
	}
	l.Warnf("Existing format on disks detected, no mkfs needed: %q", existingFormat)
	return false, nil
}

func mkfs(ctx context.Context, device string, fstype string) error {
	if fstype == "ext4" || fstype == "ext3" || fstype == "" {
		if fstype == "" {
			// Mimicing default linux behavior here
			fstype = "ext4"
		}
		args := []string{
			"-F",  // Force flag
			"-m0", // Zero blocks reserved for super-user
			device,
		}
		return runMkfs(ctx, fstype, device, args)
	} else if fstype == "xfs" {
		args := []string{
			"-f", // Force flag
			device,
		}
		return runMkfs(ctx, device, fstype, args)
	}
	return fmt.Errorf("Not implemented: unable to mkfs for format '%s'", fstype)
}

// runMkfs is modeled after the code in kubelet for formatAndMount
func runMkfs(ctx context.Context, device string, fstype string, args []string) error {
	l := logger.GetLogger(ctx)
	mkfsCmd := "mkfs." + fstype
	out, err := exec.Command(mkfsCmd, args...).CombinedOutput()
	if err == nil {
		// the disk has been formatted successfully try to mount it again.
		l.Infof("Disk successfully formatted (mkfs): %s - %s", fstype, device)
		return nil
	}
	l.WithError(fmt.Errorf("format of disk %s failed: %s - %s)", device, err, string(out)))
	return err
}

// getDiskFormat is copied from kubelet. Returns empty string if there is no filesystem
// in place, indicating it is safe to mkfs
func getDiskFormat(ctx context.Context, disk string) (string, error) {
	l := logger.GetLogger(ctx)
	args := []string{"-p", "-s", "TYPE", "-s", "PTTYPE", "-o", "export", disk}
	l.Infof("Attempting to determine if disk %q is formatted using blkid with args: (%v)", disk, args)
	dataOut, err := exec.Command("blkid", args...).CombinedOutput()
	output := string(dataOut)
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			if exit.ExitCode() == 2 {
				// Disk device is unformatted.
				// For `blkid`, if the specified token (TYPE/PTTYPE, etc) was
				// not found, or no (specified) devices could be identified, an
				// exit code of 2 is returned.
				return "", nil
			}
		}
		l.WithError(fmt.Errorf("Could not determine if disk %q is formatted (%v)", disk, err))
		return "", err
	}

	var fstype, pttype string

	lines := strings.Split(output, "\n")
	for _, l := range lines {
		if len(l) <= 0 {
			// Ignore empty line.
			continue
		}
		cs := strings.Split(l, "=")
		if len(cs) != 2 {
			return "", fmt.Errorf("blkid returns invalid output: %s", output)
		}
		// TYPE is filesystem type, and PTTYPE is partition table type, according
		// to https://www.kernel.org/pub/linux/utils/util-linux/v2.21/libblkid-docs/.
		if cs[0] == "TYPE" {
			fstype = cs[1]
		} else if cs[0] == "PTTYPE" {
			pttype = cs[1]
		}
	}

	if len(pttype) > 0 {
		l.Infof("Disk %s detected partition table type: %s", disk, pttype)
		// Returns a special non-empty string as filesystem type, then kubelet
		// will not format it.
		return "unknown data, probably partitions", nil
	}

	return fstype, nil
}

func fsck(ctx context.Context, device string, fstype string) {
	l := logger.GetLogger(ctx)
	args := []string{"-a", device}
	fsckCmd := "fsck." + fstype
	out, err := exec.Command(fsckCmd, args...).CombinedOutput()
	if err == nil {
		l.Warnf("fsck errors on %s - %s", device, string(out))
	}
	l.Infof("fsck output on %s - %s", device, string(out))
}
