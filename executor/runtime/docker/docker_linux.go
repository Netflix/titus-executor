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

	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/coreos/go-systemd/dbus"
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
	metatronServiceSystemdUnit = "titus-metatron-sync"
	sshdSystemdUnit            = "titus-sshd"
	metricStartTimeout         = time.Minute
	umountNoFollow             = 0x8
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
	tmpRet, _, err := syscall.Syscall(syscall.SYS_SCHED_SETSCHEDULER, uintptr(cred.pid), uintptr(SCHED_RR|SCHED_RESET_ON_FORK), uintptr(unsafe.Pointer(&sp))) // nolint: gosec
	ret := int(tmpRet)
	if ret == -1 {
		return err
	}

	return nil
}

func setupSystemPods(parentCtx context.Context, c *runtimeTypes.Container, cfg config.Config, cred ucred) error { // nolint: gocyclo
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
	if err := os.Mkdir(path, 0755); err != nil { // nolint: gosec
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
	// TODO: Make concurrent
	if err := startSystemdUnit(ctx, conn, false, c.TaskID, atlasSystemdUnit); err != nil {
		logrus.WithError(err).Error("Error starting atlas systemd unit")
		return err
	}
	if cfg.ContainerSSHD {
		if err := startSystemdUnit(ctx, conn, true, c.TaskID, sshdSystemdUnit); err != nil {
			logrus.WithError(err).Error("Error starting ssh systemd unit")
			return err
		}
	}
	if err := startSystemdUnit(ctx, conn, true, c.TaskID, metadataServiceSystemdUnit); err != nil {
		logrus.WithError(err).Error("Error starting metadata service systemd unit")
		return err
	}

	if shouldStartMetatronSync(&cfg, c) {
		// The metatron sync service queries the metadata server, so it needs to be started after
		if err := startSystemdUnit(ctx, conn, true, c.TaskID, metatronServiceSystemdUnit); err != nil {
			logrus.WithError(err).Error("Error starting metatron systemd unit")
			return err
		}
	}

	return nil
}

func startSystemdUnit(ctx context.Context, conn *dbus.Conn, required bool, taskID, unitName string) error {
	qualifiedUnitName := fmt.Sprintf("%s@%s.service", unitName, taskID)
	l := logrus.WithField("taskID", taskID).WithField("unit", unitName)
	l.Infof("Starting systemd unit %s", qualifiedUnitName)

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
				return fmt.Errorf("Could not start systemd unit '%s' because %s", qualifiedUnitName, val)
			}
			l.Errorf("Unknown response when starting systemd unit '%s': %s", qualifiedUnitName, val)
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
		err = os.RemoveAll(path)
		if err != nil {
			logrus.Warn("Cannot remove cgroup mount: ", err)
		}
	}

	return nil
}

func setupOOMAdj(c *runtimeTypes.Container, cred ucred) error {
	oomScore := 1000

	if c.TitusInfo.OomScoreAdj != nil {
		oomScore = int(c.TitusInfo.GetOomScoreAdj())
	}

	pid := strconv.FormatInt(int64(cred.pid), 10)
	oomScoreAdjPath := filepath.Join("/proc", pid, "oom_score_adj")
	file, err := os.OpenFile(oomScoreAdjPath, os.O_RDWR, 0000)
	if err != nil {
		return err
	}
	defer shouldClose(file)
	_, err = file.WriteString(fmt.Sprintf("%d\n", oomScore))
	return err
}
