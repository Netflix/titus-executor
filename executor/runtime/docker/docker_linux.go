// build +linux

package docker

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"io/ioutil"
	"strings"

	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/coreos/go-systemd/dbus"
	"github.com/hashicorp/go-multierror"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	SCHED_OTHER         = 0          // nolint: golint
	SCHED_FIFO          = 1          // nolint: golint
	SCHED_RR            = 2          // nolint: golint
	SCHED_BATCH         = 3          // nolint: golint
	SCHED_IDLE          = 5          // nolint: golint
	SCHED_RESET_ON_FORK = 0x40000000 // nolint: golint
)

type schedParam struct {
	schedPriority int32
}

const (
	titusInits                 = "/var/lib/titus-inits"
	atlasSystemdUnit           = "atlas-titus-agent"
	metadataServiceSystemdUnit = "titus-metadata-proxy"
	metricStartTimeout         = time.Minute
	umountNoFollow             = 0x8
	sysFsCgroup                = "/sys/fs/cgroup"
)

func getPeerInfo(unixConn *net.UnixConn) (ucred, error) {
	unixConnFile, err := unixConn.File()
	if err != nil {
		return ucred{}, err
	}

	cred, err := syscall.GetsockoptUcred(int(unixConnFile.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return ucred{}, err
	}

	retCred := ucred{
		pid: cred.Pid,
		uid: cred.Uid,
		gid: cred.Gid,
	}

	return retCred, nil
}

/* ucred should point to tini */
func setupScheduler(cred ucred) error {
	/*
	 * Processes with numerically higher priority values are scheduled before processes with
	 * numerically lower priority values.
	 */
	sp := schedParam{99}
	tmpRet, _, err := syscall.Syscall(syscall.SYS_SCHED_SETSCHEDULER, uintptr(cred.pid), uintptr(SCHED_RR|SCHED_RESET_ON_FORK), uintptr(unsafe.Pointer(&sp))) // nolint: gas
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}

	return nil
}

func setupSystemPods(parentCtx context.Context, c *runtimeTypes.Container, cred ucred) error {
	ctx, cancel := context.WithTimeout(parentCtx, metricStartTimeout)
	defer cancel()

	conn, connErr := dbus.New()
	if connErr != nil {
		return connErr
	}
	defer conn.Close()

	/* 1. Setup bind mount for Titus container task */
	// Bind mount:
	// /proc/$PID -> $titusInits/$taskID
	pidpath := filepath.Join("/proc/", strconv.FormatInt(int64(cred.pid), 10))
	path := filepath.Join(titusInits, c.TaskID)
	if err := os.Mkdir(path, 0755); err != nil { // nolint: gas
		return err
	}
	c.RegisterRuntimeCleanup(func() error {
		return os.Remove(path)
	})
	if err := unix.Mount(pidpath, path, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	c.RegisterRuntimeCleanup(func() error {
		// 0x8 is
		return unix.Unmount(path, unix.MNT_DETACH|umountNoFollow)
	})
	/* 2. Tell systemd about it */
	if err := startSystemdUnit(ctx, conn, false, c.TaskID, atlasSystemdUnit); err != nil {
		return err
	}
	if err := startSystemdUnit(ctx, conn, true, c.TaskID, metadataServiceSystemdUnit); err != nil {
		return err
	}

	return nil
}

func startSystemdUnit(ctx context.Context, conn *dbus.Conn, required bool, taskID, unitName string) error {
	qualifiedUnitName := fmt.Sprintf("%s@%s.service", unitName, taskID)
	logrus.WithField("taskID", taskID).WithField("unit", unitName).Debug("Starting unit")
	ch := make(chan string, 1)
	if _, err := conn.StartUnit(qualifiedUnitName, "fail", ch); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case val := <-ch:
		if val != "done" {
			if required {
				return fmt.Errorf("Could not start systemd unit '%s' because %s", unitName, val)
			}
			logrus.WithField("taskID", taskID).Error("Unknown response when starting systemd unit: ", val)
		}
	}
	return nil
}

func getOwnCgroup(subsystem string) (string, error) {
	return cgroups.GetOwnCgroup(subsystem)
}

func cleanupCgroups(cgroupPath string) error {
	allCgroupMounts, err := cgroups.GetCgroupMounts(true)
	if err != nil {
		logrus.Error("Cannot get cgroup mounts: ", err)
		return err
	}
	for _, mount := range allCgroupMounts {
		path := filepath.Join(mount.Mountpoint, cgroupPath)
		_ = os.RemoveAll(path)
	}

	return nil
}

func setupContainerNesting(parentCtx context.Context, c *runtimeTypes.Container, cred ucred) error {
	if !c.TitusInfo.GetAllowNestedContainers() {
		return nil
	}
	cgroupPath := filepath.Join("/proc/", strconv.FormatInt(int64(cred.pid), 10), "cgroup")
	cgroups, err := ioutil.ReadFile(cgroupPath)
	if err != nil {
		return err
	}
	var ret error
	for _, line := range strings.Split(string(cgroups), "\n") {
		cgroupInfo := strings.Split(strings.TrimSpace(line), ":")
		if len(cgroupInfo) != 3 {
			continue
		}
		controllerType := cgroupInfo[1]
		if len(controllerType) == 0 {
			continue
		}
		// This is to handle the name=systemd cgroup, we should probably parse /proc/mounts, but this is a little bit easier
		controllerType = strings.TrimPrefix(controllerType, "name=")
		controllerPath := cgroupInfo[2]
		fsPath := filepath.Join(sysFsCgroup, controllerType, controllerPath)
		err = os.Chown(fsPath, int(cred.uid), int(cred.gid))
		if err != nil {
			ret = multierror.Append(ret, err)
		}
	}

	return ret
}
