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
	"github.com/ShinyTrinkets/overseer"
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
	initCommand  string
	required     bool
	unitName     string
	enabledCheck serviceEnabledFunc
	command      string
	notify       bool
	nsenter      bool
}

const (
	titusInits                = "/var/lib/titus-inits"
	systemServiceStartTimeout = 90 * time.Second
	umountNoFollow            = 0x8
	sysFsCgroup               = "/sys/fs/cgroup"
	runcArgFormat             = "--root /var/run/docker/runtime-%s/moby exec --user 0:0 --cap CAP_DAC_OVERRIDE %s %s"
	defaultOomScore           = 1000
)

// TODO: get this data from some other place, like docker labels or config maps or maybe just a json file to start
var systemServices = []serviceOpts{
	{
		unitName:     "titus-spectatord",
		enabledCheck: shouldStartSpectatord,
		required:     false,
		command:      "/titus/spectatord/start-spectatord",
	},
	{
		unitName:     "titus-atlasd",
		enabledCheck: shouldStartAtlasd,
		required:     false,
		command:      "/titus/atlas-titus-agent/start-atlas-titus-agent",
		nsenter:      true,
	},
	{
		unitName:     "atlas-titus-agent",
		enabledCheck: shouldStartAtlasAgent,
		required:     false,
		command:      "/usr/local/bin/atlas-titus-agent",
	},
	{
		unitName:     "titus-sshd",
		enabledCheck: shouldStartSSHD,
		required:     false,
		command:      "/titus/sshd/usr/sbin/sshd -D -e",
		nsenter:      true,
	},
	{
		unitName: "titus-metadata-proxy",
		required: true,
		command:  "/apps/titus-executor/bin/run-titus-metadata-proxy.sh",
		notify:   true,
	},
	{
		unitName:     "titus-metatron-sync",
		required:     true,
		initCommand:  "/titus/metatron/bin/titus-metatrond --init",
		enabledCheck: shouldStartMetatronSync,
		command:      " /titus/metatron/bin/titus-metatrond",
		nsenter:      true,
	},
	{
		unitName:     "titus-logviewer",
		required:     true,
		enabledCheck: shouldStartLogViewer,
		command:      "bin/adminlogs",
		nsenter:      true,
	},
	{
		unitName:     "titus-servicemesh",
		required:     true,
		enabledCheck: shouldStartServiceMesh,
		command:      "/titus/proxyd/launcher",
		nsenter:      true,
	},
	{
		unitName:     "titus-abmetrix",
		required:     false,
		enabledCheck: shouldStartAbmetrix,
		command:      "/titus/abmetrix/start",
		nsenter:      true,
	},
	{
		unitName:     "titus-seccomp-agent",
		required:     true,
		enabledCheck: shouldStartTitusSeccompAgent,
		command:      "/usr/bin/tsa",
	},
	{
		unitName:     "titus-storage",
		required:     true,
		enabledCheck: shouldStartTitusStorage,
		command:      "/apps/titus-executor/bin/titus-storage start",
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
		if err := startSystemService(ctx, c.TaskID(), c.ID(), runtime, svc); err != nil {
			logrus.WithError(err).Errorf("Error starting %s service", svc.unitName)
			return err
		}
		// TODO: Somehow get the overseer object back out so that we can see the
		// status and expose it via pod status.conditions
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
			return errors.Wrapf(err, "error starting %s service: %s", opts.unitName, errStr)
		}

		return errors.Wrapf(err, "error starting %s service", opts.unitName)
	}

	return nil
}

func (s serviceOpts) generateFullCommand() string {
	// TODO: Compose the full command, including moby, nsenter and junk
	return s.command
}

func startSystemService(ctx context.Context, taskID string, cID string, runtime string, opts serviceOpts) error {
	qualifiedUnitName := fmt.Sprintf("%s@%s.service", opts.unitName, taskID)
	l := logrus.WithFields(logrus.Fields{
		"containerId": cID,
		"taskID":      taskID,
		"unit":        opts.unitName,
	})

	if err := runServiceInitCommand(ctx, l, cID, runtime, opts); err != nil {
		return err
	}

	timeout := 5 * time.Second
	if opts.required {
		timeout = 30 * time.Second
	}

	l.Infof("starting systemd unit %s", qualifiedUnitName)
	ch := startAndSupervise(qualifiedUnitName, opts.generateFullCommand())
	select {
	case <-ctx.Done():
		doneErr := ctx.Err()
		if doneErr == context.DeadlineExceeded {
			if opts.required {
				return errors.Wrapf(doneErr, "timeout (overall task start dealine exceeded) starting %s service", opts.unitName)
			}
			l.Errorf("timeout (overall task start dealine exceeded) starting %s service (not required to launch this task)", opts.unitName)
			return nil
		}
		return doneErr
	case val := <-ch:
		if val != "done" {
			if opts.required {
				return fmt.Errorf("could not start %s service (%s): %s", opts.unitName, qualifiedUnitName, val)
			}
			l.Errorf("unknown response when starting systemd unit '%s': %s", qualifiedUnitName, val)
		}
	case <-time.After(timeout):
		if opts.required {
			return fmt.Errorf("timeout after %d seconds starting %s service (which is required to start)", timeout, opts.unitName)
		}
		l.Errorf("timeout after %d seconds starting %s service (not required to launch this task)", timeout, opts.unitName)
		return nil
	}
	return nil
}

func startAndSupervise(unitName string, command string) <-chan string {
	o := overseer.NewOverseer()
	// TODO: Copy these from the unit files
	options := overseer.Options{
		Group:      "",
		Dir:        "",
		Env:        []string{},
		DelayStart: 0,
		RetryTimes: 0,
		Buffered:   false,
		Streaming:  false,
	}
	runnableCmd := o.Add(unitName, command, options)

	stdoutChan := make(chan string, 100)
	go func() {
		for line := range stdoutChan {
			// TODO: use the journal hook somehow to pipe this to the right place
			logrus.Info(line)
		}
	}()
	stdout := overseer.NewOutputStream(stdoutChan)
	runnableCmd.Stdout = stdout

	go o.SuperviseAll()

	c := make(chan string)
	o.Watch(c)
	return c
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
