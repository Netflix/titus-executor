// build +linux

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
	"github.com/coreos/go-systemd/dbus"
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

// Function to determine if a service should be enabled or not
type serviceEnabledFunc func(cfg *config.Config, c *runtimeTypes.Container) bool

type serviceOpts struct {
	humanName    string
	initCommand  string
	required     bool
	unitName     string
	enabledCheck serviceEnabledFunc
}

const (
	titusInits                = "/var/lib/titus-inits"
	systemServiceStartTimeout = 90 * time.Second
	umountNoFollow            = 0x8
	sysFsCgroup               = "/sys/fs/cgroup"
	runcArgFormat             = "--root /var/run/docker/runtime-%s/moby exec --user 0:0 --cap CAP_DAC_OVERRIDE %s %s"
)

var systemServices = []serviceOpts{
	{
		humanName: "atlas",
		unitName:  "atlas-titus-agent",
	},
	{
		humanName: "ssh",
		unitName:  "titus-sshd",
		required:  true,
		enabledCheck: func(cfg *config.Config, c *runtimeTypes.Container) bool {
			return cfg.ContainerSSHD
		},
	},
	{
		humanName: "metadata proxy",
		unitName:  "titus-metadata-proxy",
		required:  true,
	},
	{
		humanName:    "metatron",
		unitName:     "titus-metatron-sync",
		required:     true,
		initCommand:  "/titus/metatron/bin/titus-metatrond --init",
		enabledCheck: shouldStartMetatronSync,
	},
	{
		humanName: "logviewer",
		unitName:  "titus-logviewer",
		required:  true,
		enabledCheck: func(cfg *config.Config, c *runtimeTypes.Container) bool {
			return cfg.ContainerLogViewer
		},
	},
}

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
func mountContainerProcPid1InTitusInits(parentCtx context.Context, c *runtimeTypes.Container, cred ucred) error {
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

	return nil
}

func setupSystemServices(parentCtx context.Context, c *runtimeTypes.Container, cfg config.Config, cred ucred) error { // nolint: gocyclo
	ctx, cancel := context.WithTimeout(parentCtx, systemServiceStartTimeout)
	defer cancel()

	conn, connErr := dbus.New()
	if connErr != nil {
		return connErr
	}
	defer conn.Close()

	for _, svc := range systemServices {
		if svc.enabledCheck != nil && !svc.enabledCheck(&cfg, c) {
			continue
		}

		// Different runtimes have different root paths that need to be passed to runc with `--root`.
		// In particular, we use the `oci-add-hooks` runtime for GPU containers.
		runtime := runtimeTypes.DefaultOciRuntime
		if c.Runtime != "" {
			runtime = c.Runtime
		}
		if err := startSystemdUnit(ctx, conn, c.TaskID, c.ID, runtime, svc); err != nil {
			logrus.WithError(err).Errorf("Error starting %s service", svc.humanName)
			return err
		}
	}

	return nil
}

func runServiceInitCommand(ctx context.Context, log *logrus.Entry, cID string, runtime string, opts serviceOpts) error {
	if opts.initCommand == "" {
		return nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	l := log.WithField("initCommand", opts.initCommand)
	cmdArgStr := fmt.Sprintf(runcArgFormat, runtime, cID, opts.initCommand)
	cmdArgs := strings.Split(cmdArgStr, " ")

	runcCommand, err := exec.LookPath(runtimeTypes.DefaultOciRuntime)
	if err != nil {
		return err
	}

	l.WithField("args", cmdArgStr).Infof("Running init command for %s service", opts.unitName)
	cmd := exec.CommandContext(ctx, runcCommand, cmdArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		outputStr := stdout.String()
		l.WithError(err).WithField("exitCode", cmd.ProcessState.ExitCode()).Errorf("error running init command for %s service", opts.unitName)
		l.Infof("%s service stdout: %s", opts.unitName, outputStr)
		l.Infof("%s service sterr: %s", opts.unitName, stderr.String())

		if len(outputStr) != 0 {
			// Find the last non-empty line in stdout and use that as the error message
			splitOutput := strings.Split(strings.TrimSuffix(strings.TrimSpace(outputStr), "\n"), "\n")
			errStr := splitOutput[len(splitOutput)-1]
			return errors.Wrapf(err, "error starting %s service: %s", opts.humanName, errStr)
		}

		return errors.Wrapf(err, "error starting %s service", opts.humanName)
	}

	return nil
}

func startSystemdUnit(ctx context.Context, conn *dbus.Conn, taskID string, cID string, runtime string, opts serviceOpts) error {
	qualifiedUnitName := fmt.Sprintf("%s@%s.service", opts.unitName, taskID)
	l := logrus.WithFields(logrus.Fields{
		"containerId": cID,
		"taskID":      taskID,
		"unit":        opts.unitName,
	})

	if err := runServiceInitCommand(ctx, l, cID, runtime, opts); err != nil {
		return err
	}

	l.Infof("Starting systemd unit %s", qualifiedUnitName)
	ch := make(chan string, 1)
	if _, err := conn.StartUnit(qualifiedUnitName, "fail", ch); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		doneErr := ctx.Err()

		if doneErr == context.DeadlineExceeded {
			return errors.Wrapf(doneErr, "timeout starting %s service", opts.humanName)
		}
		return doneErr
	case val := <-ch:
		if val != "done" {
			if opts.required {
				return fmt.Errorf("could not start %s service (%s): %s", opts.humanName, qualifiedUnitName, val)
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

func setCgroupOwnership(parentCtx context.Context, c *runtimeTypes.Container, cred ucred) error {
	if !c.IsSystemD {
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
