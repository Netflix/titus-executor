// build +linux

package docker

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
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
type serviceEnabledFunc func(cfg *config.Config, c runtimeTypes.Container) bool

type serviceOpts struct {
	humanName    string
	required     bool
	unitName     string
	enabledCheck serviceEnabledFunc
}

const (
	titusInits                = "/var/lib/titus-inits"
	systemServiceStartTimeout = 90 * time.Second
	umountNoFollow            = 0x8
	sysFsCgroup               = "/sys/fs/cgroup"
	defaultOomScore           = 1000
)

var systemServices = []serviceOpts{
	{
		humanName:    "spectatord",
		unitName:     "titus-spectatord",
		enabledCheck: shouldStartSpectatord,
		required:     false,
	},
	{
		humanName:    "atlas",
		unitName:     "titus-atlasd",
		enabledCheck: shouldStartAtlasd,
		required:     false,
	},
	{
		humanName:    "atlas",
		unitName:     "atlas-titus-agent",
		enabledCheck: shouldStartAtlasAgent,
		required:     false,
	},
	{
		humanName:    "ssh",
		unitName:     "titus-sshd",
		enabledCheck: shouldStartSSHD,
		required:     false,
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
		enabledCheck: shouldStartMetatronSync,
	},
	{
		humanName:    "logviewer",
		unitName:     "titus-logviewer",
		required:     true,
		enabledCheck: shouldStartLogViewer,
	},
	{
		humanName:    "service mesh",
		unitName:     "titus-servicemesh",
		required:     true,
		enabledCheck: shouldStartServiceMesh,
	},
	{
		humanName:    "abmetrix",
		unitName:     "titus-abmetrix",
		required:     false,
		enabledCheck: shouldStartAbmetrix,
	},
	{
		humanName:    "seccomp agent",
		unitName:     "titus-seccomp-agent",
		required:     true,
		enabledCheck: shouldStartTitusSeccompAgent,
	},
	{
		humanName:    "titus-storage",
		unitName:     "titus-storage",
		required:     true,
		enabledCheck: shouldStartTitusStorage,
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
func (r *DockerRuntime) mountContainerProcPid1InTitusInits(parentCtx context.Context, c runtimeTypes.Container, cred ucred) error {
	pidpath := filepath.Join("/proc/", strconv.FormatInt(int64(cred.pid), 10))
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

func setupSystemServices(parentCtx context.Context, c runtimeTypes.Container, cfg config.Config, cred ucred) error { // nolint: gocyclo
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
		if r := c.Runtime(); r != "" {
			runtime = r
		}
		if err := startSystemdUnit(ctx, conn, c.TaskID(), c.ID(), runtime, svc); err != nil {
			logrus.WithError(err).Errorf("Error starting %s service", svc.humanName)
			return err
		}
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

	timeout := 5 * time.Second
	if opts.required {
		timeout = 30 * time.Second
	}

	l.Infof("starting systemd unit %s", qualifiedUnitName)
	ch := make(chan string, 1)
	if _, err := conn.StartUnit(qualifiedUnitName, "fail", ch); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		doneErr := ctx.Err()
		if doneErr == context.DeadlineExceeded {
			if opts.required {
				return errors.Wrapf(doneErr, "timeout (overall task start dealine exceeded) starting %s service", opts.humanName)
			}
			l.Errorf("timeout (overall task start dealine exceeded) starting %s service (not required to launch this task)", opts.humanName)
			return nil
		}
		return doneErr
	case val := <-ch:
		if val != "done" {
			if opts.required {
				return fmt.Errorf("could not start %s service (%s): %s", opts.humanName, qualifiedUnitName, val)
			}
			l.Errorf("unknown response when starting systemd unit '%s': %s", qualifiedUnitName, val)
		}
	case <-time.After(timeout):
		if opts.required {
			return fmt.Errorf("timeout after %d seconds starting %s service (which is required to start)", timeout, opts.humanName)
		}
		l.Errorf("timeout after %d seconds starting %s service (not required to launch this task)", timeout, opts.humanName)
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
		err = os.RemoveAll(path)
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
		return err
	}
	defer shouldClose(file)
	_, err = file.WriteString(fmt.Sprintf("%d\n", oomScore))
	return err
}
