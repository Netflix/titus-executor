//go:build linux && !noroot
// +build linux,!noroot

package docker

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/pkg/errors"
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
	titusInits                = "/var/lib/titus-inits"
	systemServiceStartTimeout = 90 * time.Second
	umountNoFollow            = 0x8
	sysFsCgroup               = "/sys/fs/cgroup"
	runcArgFormat             = "--root /var/run/docker/runtime-%s/moby exec --user 0:0 --cap CAP_DAC_OVERRIDE %s %s"
	defaultOomScore           = 1000
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

// This mounts /proc/${PID1}/ to /var/lib/titus-inits for the container
func (r *DockerRuntime) mountContainerProcPid1InTitusInits(parentCtx context.Context, c runtimeTypes.Container, cred ucred) error {
	pidpath := filepath.Join("/proc", strconv.FormatInt(int64(cred.pid), 10))
	path := filepath.Join(titusInits, c.TaskID())
	if err := os.Mkdir(path, 0755); err != nil { // nolint: gosec
		return err
	}
	r.registerRuntimeCleanup(func() error {
		return os.Remove(path)
	})
	if err := unix.Mount(pidpath, path, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	r.registerRuntimeCleanup(func() error {
		// 0x8 is
		return unix.Unmount(path, unix.MNT_DETACH|umountNoFollow)
	})

	return nil
}

func stopSystemServices(ctx context.Context, c runtimeTypes.Container) error {
	ctx, cancel := context.WithTimeout(ctx, systemServiceStartTimeout)
	defer cancel()

	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	target := fmt.Sprintf("titus-container@%s.target", c.TaskID())
	_, err = conn.StopUnitContext(ctx, target, "fail", nil)
	if err != nil {
		return fmt.Errorf("Could not stop target %q: %w", target, err)
	}

	return nil
}

func setupSystemServices(parentCtx context.Context, c runtimeTypes.Container, cfg config.Config) error { // nolint: gocyclo
	ctx, cancel := context.WithTimeout(parentCtx, systemServiceStartTimeout)
	defer cancel()

	conn, connErr := dbus.NewWithContext(ctx)
	if connErr != nil {
		return connErr
	}
	defer conn.Close()

	// TODO: it would be nice not to fetch this twice
	systemServices, err := c.SystemServices()
	if err != nil {
		return err
	}
	// TODO: Can we somehow make sure titus-container always starts first?
	for _, svc := range systemServices {
		if svc.EnabledCheck != nil && !svc.EnabledCheck(&cfg, c) {
			logrus.Debugf("skipping system service %s, not enabled", svc.ServiceName)
			continue
		}
		if svc.UnitName == "" {
			continue
		}

		// Different runtimes have different root paths that need to be passed to runc with `--root`.
		// In particular, we use the `oci-add-hooks` runtime for GPU containers.
		runtime := runtimeTypes.DefaultOciRuntime
		if r := c.Runtime(); r != "" {
			runtime = r
		}
		if err := startSystemdUnit(ctx, conn, c.TaskID(), c.ID(), runtime, *svc); err != nil {
			logrus.WithError(err).Errorf("Error starting %s service", svc.UnitName)
			return err
		}
	}

	return nil
}

func runServiceInitCommand(ctx context.Context, log *logrus.Entry, cID string, runtime string, opts runtimeTypes.ServiceOpts) error {
	if opts.InitCommand == "" {
		return nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	l := log.WithField("initCommand", opts.InitCommand)
	cmdArgStr := fmt.Sprintf(runcArgFormat, runtime, cID, opts.InitCommand)
	cmdArgs := strings.Split(cmdArgStr, " ")

	runcCommand, err := exec.LookPath(runtimeTypes.DefaultOciRuntime)
	if err != nil {
		return err
	}

	l.WithField("args", cmdArgStr).Infof("Running init command for %s service", opts.UnitName)
	cmd := exec.CommandContext(ctx, runcCommand, cmdArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		outputStr := stdout.String()
		l.WithError(err).WithField("exitCode", cmd.ProcessState.ExitCode()).Errorf("error running init command for %s service", opts.UnitName)
		l.Infof("%s service stdout: %s", opts.UnitName, outputStr)
		l.Infof("%s service sterr: %s", opts.UnitName, stderr.String())

		if len(outputStr) != 0 {
			// Find the last non-empty line in stdout and use that as the error message
			splitOutput := strings.Split(strings.TrimSuffix(strings.TrimSpace(outputStr), "\n"), "\n")
			errStr := splitOutput[len(splitOutput)-1]
			return errors.Wrapf(err, "error starting %s service: %s", opts.UnitName, errStr)
		}

		return errors.Wrapf(err, "error starting %s service", opts.UnitName)
	}

	return nil
}

func startSystemdUnit(ctx context.Context, conn *dbus.Conn, taskID string, cID string, runtime string, opts runtimeTypes.ServiceOpts) error {
	postFix := "service"
	if opts.Target {
		postFix = "target"
	}
	qualifiedUnitName := fmt.Sprintf("%s@%s.%s", opts.UnitName, taskID, postFix)
	l := logrus.WithFields(logrus.Fields{
		"containerId": cID,
		"taskID":      taskID,
		"unit":        opts.UnitName,
	})

	if err := runServiceInitCommand(ctx, l, cID, runtime, opts); err != nil {
		return err
	}

	timeout := 5 * time.Second
	if opts.Required {
		timeout = 30 * time.Second
	}

	l.Infof("starting systemd unit %s", qualifiedUnitName)
	ch := make(chan string, 1)
	if _, err := conn.StartUnitContext(ctx, qualifiedUnitName, "fail", ch); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		doneErr := ctx.Err()
		if doneErr == context.DeadlineExceeded {
			if opts.Required {
				return errors.Wrapf(doneErr, "timeout (overall task start dealine exceeded) starting %s service", opts.UnitName)
			}
			l.Errorf("timeout (overall task start dealine exceeded) starting %s service (not required to launch this task)", opts.UnitName)
			return nil
		}
		return doneErr
	case val := <-ch:
		if val != "done" {
			if opts.Required {
				return fmt.Errorf("could not start %s service (%s): %s", opts.UnitName, qualifiedUnitName, val)
			}
			l.Errorf("unknown response when starting systemd unit '%s': %s", qualifiedUnitName, val)
		}
	case <-time.After(timeout):
		if opts.Required {
			return fmt.Errorf("timeout after %d seconds starting %s service (which is required to start)", timeout/time.Second, opts.UnitName)
		}
		l.Errorf("timeout after %d seconds starting %s service (not required to launch this task)", timeout/time.Second, opts.UnitName)
		return nil
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
		err = cgroups.RemovePath(path)
		if err != nil {
			logrus.Warn("Cannot remove cgroup mount: ", err)
		}
	}

	return nil
}

func setCgroupOwnership(parentCtx context.Context, c runtimeTypes.Container, cred ucred) error {
	if !c.IsSystemD() {
		return nil
	}

	cgroupPath := filepath.Join("/proc/", strconv.Itoa(int(cred.pid)), "cgroup")
	cgroups, err := ioutil.ReadFile(cgroupPath) // nolint: gosec
	if err != nil {
		logrus.WithError(err).Error("Could not read container cgroups")
		return err
	}
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
		if controllerType != "systemd" {
			continue
		}

		// systemd needs to be the owner of its systemd cgroup in order to start up
		controllerPath := cgroupInfo[2]
		fsPath := filepath.Join(sysFsCgroup, controllerType, controllerPath)
		logrus.Infof("chowning systemd cgroup path: %s", fsPath)
		err = os.Chown(fsPath, int(cred.uid), int(cred.gid))
		if err != nil {
			logrus.WithError(err).Error("Could not chown systemd cgroup path")
		}
		return err
	}

	return nil
}

func setupOOMAdj(c runtimeTypes.Container, cred ucred) error {
	oomScore := defaultOomScore

	if oomScoreAdj := c.OomScoreAdj(); oomScoreAdj != nil {
		oomScore = int(*oomScoreAdj)
	}

	pid := strconv.FormatInt(int64(cred.pid), 10)
	oomScoreAdjPath := filepath.Join("/proc", pid, "oom_score_adj")
	file, err := os.OpenFile(oomScoreAdjPath, os.O_RDWR, 0000)
	if err != nil {
		err = fmt.Errorf("Failed to open oom_score_adj: %w", err)
		return err
	}
	defer shouldClose(file)
	_, err = file.WriteString(fmt.Sprintf("%d\n", oomScore))
	if err != nil {
		err = fmt.Errorf("Failed to set oom_score_adj: %w", err)
	}
	return err
}

func MountTmpfs(path string, size string) error {
	var flags uintptr
	flags = syscall.MS_NOATIME | syscall.MS_SILENT
	flags |= syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID
	options := "size=" + size
	err := syscall.Mount("tmpfs", path, "tmpfs", flags, options)
	return os.NewSyscallError("mount", err)
}

func UnmountLazily(path string) error {
	return unix.Unmount(path, unix.MNT_DETACH|umountNoFollow)
}
