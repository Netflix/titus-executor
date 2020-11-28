package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/nvidia"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	docker "github.com/docker/docker/client"
	"github.com/docker/go-units"
	"github.com/ftrvxmtrx/fd"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

var (
	_                   runtimeTypes.Runtime = (*DockerRuntime)(nil)
	errMissingResources                      = errors.New("Missing container resources")
)

// units
const (
	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB

	KB = 1000
	MB = 1000 * KB
	GB = 1000 * MB
)

const (
	fuseDev = "/dev/fuse"
	kvmDev  = "/dev/kvm"
	tunDev  = "/dev/net/tun"
	// See: TITUS-1231, this is added as extra padding for container initialization
	builtInDiskBuffer       = 1100 // In megabytes, includes extra space for /logs.
	defaultNetworkBandwidth = 128 * MB
	defaultKillWait         = 10 * time.Second
	defaultRunTmpFsSize     = "134217728" // 128 MiB
	defaultRunLockTmpFsSize = "5242880"   // 5 MiB: the default setting on Ubuntu Xenial
	trueString              = "true"
	systemdImageLabel       = "com.netflix.titus.systemd"
)

// cleanupFunc can be registered to be called on container teardown, errors are reported, but not acted upon
type cleanupFunc func() error

// NoEntrypointError indicates that the Titus job does not have an entrypoint, or command
var NoEntrypointError = &runtimeTypes.BadEntryPointError{Reason: errors.New("Image, and job have no entrypoint, or command")}

// I'm sorry for using regex, it's a simple rule though
// 1. The string must start with a-z, A-Z, or _
// 2. The string MAY contain more characters, in the set a-z, A-Z, 0-9, or _
// 3. ^ checks from the beginning of the string and $ checks for the end of the string -- This way, we can make sure the entire thing matches.

// The rules, as from the POSIX standard:
// Environment variable names used by the utilities in the Shell and Utilities volume of IEEE Std 1003.1-2001
// consist solely of uppercase letters, digits, and the ‘_’ (underscore) from the characters defined in
// Portable Character Set and do not begin with a digit. Other characters may be permitted by an implementation;
// applications shall tolerate the presence of such names.
var environmentVariableKeyRegexp = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*$")

// Poor man's OS compat
type ucred struct {
	pid int32
	uid uint32
	gid uint32
}

// DockerRuntime implements the Runtime interface calling Docker Engine APIs
type DockerRuntime struct { // nolint: golint
	// Following fields to be set when NewDockerRuntime is called
	metrics           metrics.Reporter
	registryAuthCfg   *types.AuthConfig
	client            *docker.Client
	awsRegion         string
	tiniSocketDir     string
	tiniEnabled       bool
	storageOptEnabled bool
	pidCgroupPath     string
	cfg               config.Config
	dockerCfg         Config

	// cleanup callbacks that runtime implementations can register to do cleanup
	cleanupFuncLock sync.Mutex
	cleanup         []cleanupFunc

	// To be set when initializing a specific instance of the runtime provider
	c          runtimeTypes.Container
	startTime  time.Time
	gpuManager runtimeTypes.GPUManager
}

type Opt func(ctx context.Context, runtime *DockerRuntime) error

func WithGPUManager(gpuManager runtimeTypes.GPUManager) Opt {
	return func(ctx context.Context, runtime *DockerRuntime) error {
		runtime.gpuManager = gpuManager
		return nil
	}
}

// NewDockerRuntime provides a Runtime implementation on Docker.
func NewDockerRuntime(ctx context.Context, m metrics.Reporter, dockerCfg Config, cfg config.Config, dockerOpts ...Opt) (runtimeTypes.ContainerRuntimeProvider, error) {
	log.Info("New Docker client, to host ", cfg.DockerHost)
	client, err := docker.NewClient(cfg.DockerHost, "1.26", nil, map[string]string{})

	if err != nil {
		return nil, err
	}

	info, err := client.Info(ctx)

	if err != nil {
		return nil, err
	}

	pidCgroupPath, err := getOwnCgroup("pids")
	if err != nil {
		return nil, err
	}

	// TODO: Check
	awsRegion := os.Getenv("EC2_REGION")
	storageOptEnabled := shouldEnableStorageOpts(info)

	runtimeFunc := func(ctx context.Context, c runtimeTypes.Container, startTime time.Time) (runtimeTypes.Runtime, error) {
		dockerRuntime := &DockerRuntime{
			pidCgroupPath:     pidCgroupPath,
			awsRegion:         awsRegion,
			metrics:           m,
			registryAuthCfg:   nil, // we don't need registry authentication yet
			client:            client,
			cfg:               cfg,
			dockerCfg:         dockerCfg,
			cleanup:           []cleanupFunc{},
			c:                 c,
			startTime:         startTime,
			storageOptEnabled: storageOptEnabled,
		}

		if strings.Contains(info.InitBinary, "tini") {
			dockerRuntime.tiniEnabled = true
		} else {
			log.WithField("initBinary", info.InitBinary).Warning("Docker runtime disabling Tini support")
		}

		for _, dockerOpt := range dockerOpts {
			err := dockerOpt(ctx, dockerRuntime)
			if err != nil {
				return nil, err
			}
		}

		if dockerRuntime.gpuManager == nil {
			dockerRuntime.gpuManager, err = nvidia.NewNvidiaInfo(ctx, dockerCfg.nvidiaOciRuntime)
			if err != nil {
				return nil, fmt.Errorf("GPU Manager unset, failed to initialize default (nvidia) GPU manager: %w", err)
			}
		}

		// Don't reference captured error variable from above
		err := setupLoggingInfra(dockerRuntime)
		if err != nil {
			return nil, err
		}
		dockerRuntime.registerRuntimeCleanup(func() error {
			err = os.RemoveAll(dockerRuntime.tiniSocketDir)
			if err != nil {
				log.WithError(err).Errorf("Could not cleanup tini socket directory %s", dockerRuntime.tiniSocketDir)
				return err
			}
			return nil
		})
		return dockerRuntime, nil
	}

	return runtimeFunc, nil
}

func shouldEnableStorageOpts(info types.Info) bool {
	// XFS + Overlayfs also supports this, but we don't have that yet
	// It's slightly more complicated because it requires checking not only the driver, but also the underlying
	// FS
	switch strings.ToLower(info.Driver) {
	case "btrfs":
		return true
	case "zfs":
		return true
	case "overlay2":
		// We need to make sure the underlying filesystem is XFS and that the underlying device
		// has project quotas enabled
		if hasProjectQuotasEnabled(info.DockerRootDir) {
			return true
		}
	}
	return false
}

// RegisterRuntimeCleanup calls registered functions whether or not the container successfully starts
func (r *DockerRuntime) registerRuntimeCleanup(callback cleanupFunc) {
	r.cleanupFuncLock.Lock()
	defer r.cleanupFuncLock.Unlock()
	r.cleanup = append(r.cleanup, callback)
}

func (r *DockerRuntime) validateEFSMounts(c runtimeTypes.Container) error {
	if len(c.EfsConfigInfo()) > 0 && !r.tiniEnabled {
		return errors.New("Tini Disabled; Cannot setup EFS volume")
	}

	return nil
}

func setupLoggingInfra(dockerRuntime *DockerRuntime) error {
	var err error
	dockerRuntime.tiniSocketDir, err = ioutil.TempDir("/var/tmp", "titus-executor-sockets")
	if err != nil {
		return err
	}

	err = os.Chmod(dockerRuntime.tiniSocketDir, 0777) // nolint: gosec
	if err != nil {
		return err
	}

	err = os.Mkdir(dockerRuntime.cfg.LogsTmpDir, 0777) // nolint: gosec
	if err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func maybeSetCFSBandwidth(cfsBandwidthPeriod uint64, c runtimeTypes.Container, hostCfg *container.HostConfig) {
	cpuBurst := c.AllowCPUBursting()
	logEntry := log.WithField("taskID", c.TaskID()).WithField("cpuBurst", cpuBurst)

	if cpuBurst {
		logEntry.Info("Falling back to shares since CPU bursting is enabled")
		setShares(logEntry, c, hostCfg)
		return
	}

	setCFSBandwidth(logEntry, cfsBandwidthPeriod, c, hostCfg)
}

func setCFSBandwidth(logEntry *log.Entry, cfsBandwidthPeriod uint64, c runtimeTypes.Container, hostCfg *container.HostConfig) {
	quota := int64(cfsBandwidthPeriod) * c.Resources().CPU
	if quota <= 0 {
		logEntry.Error("Invalid CPU quota configuration")
		setNanoCPUs(logEntry, c, hostCfg)
		return
	}

	logEntry.WithField("quota", quota).WithField("period", cfsBandwidthPeriod).Info("Configuring with CFS Bandwidth")

	if cfsBandwidthPeriod < 1000 || cfsBandwidthPeriod > 1000000 {
		logEntry.WithField("quota", quota).WithField("period", cfsBandwidthPeriod).Error("Invalid CFS Bandwidth, falling back to NanoCPUs")
		setNanoCPUs(logEntry, c, hostCfg)
		return
	}

	hostCfg.CPUPeriod = int64(cfsBandwidthPeriod)
	hostCfg.CPUQuota = quota
}

func setNanoCPUs(logEntry *log.Entry, c runtimeTypes.Container, hostCfg *container.HostConfig) {
	nanoCPUs := c.Resources().CPU * 1e9
	logEntry.WithField("nanoCPUs", nanoCPUs).Info("Setting Nano CPUs")
	// TODO: Verify that .CPUPeriod, and .CPUQuota are not set
	hostCfg.NanoCPUs = nanoCPUs
}

func setShares(logEntry *log.Entry, c runtimeTypes.Container, hostCfg *container.HostConfig) {
	shares := c.Resources().CPU * 100
	logEntry.WithField("shares", shares).Info("Setting shares")
	hostCfg.CPUShares = shares
}

func stableSecret() string {
	ipBuf := make([]byte, 16)
	// We can use math/rand here because this doesn't have to be cryptographically secure
	n, err := rand.Read(ipBuf) // nolint: gosec
	if err != nil {
		panic(err)
	}
	if n != len(ipBuf) {
		panic(fmt.Sprintf("rand.Read only read %d bytes, not %d bytes", n, len(ipBuf)))
	}
	return net.IP(ipBuf).String()
}

func (r *DockerRuntime) dockerConfig(c runtimeTypes.Container, binds []string, imageSize int64, volumeContainers []string) (*container.Config, *container.HostConfig, error) { // nolint: gocyclo
	// Extract the entrypoint from the proto. If the proto is empty, pass
	// an empty entrypoint and let Docker extract it from the image.
	entrypoint, cmd := c.Process()

	// hostname style: ip-{ip-addr} or {task ID}
	hostname, err := runtimeTypes.ComputeHostname(c)
	if err != nil {
		return nil, nil, err
	}

	containerCfg := &container.Config{
		Image:      c.QualifiedImageName(),
		Entrypoint: entrypoint,
		Cmd:        cmd,
		Labels:     c.Labels(),
		Volumes:    map[string]struct{}{},
		Hostname:   hostname,
		Tty:        c.TTYEnabled(),
	}

	useInit := true
	hostCfg := &container.HostConfig{
		AutoRemove: false,
		Privileged: false,
		Binds:      binds,
		ExtraHosts: []string{},
		DNS:        []string{"169.254.169.253"},
		Sysctls: map[string]string{
			"net.ipv4.tcp_ecn":                    "1",
			"net.ipv6.conf.all.disable_ipv6":      "0",
			"net.ipv6.conf.default.disable_ipv6":  "0",
			"net.ipv6.conf.lo.disable_ipv6":       "0",
			"net.ipv6.conf.default.stable_secret": stableSecret(), // This is to ensure each container sets their addresses differently
			"net.ipv6.conf.all.use_tempaddr":      "0",
			"net.ipv6.conf.default.use_tempaddr":  "0",
			"net.ipv6.conf.default.accept_dad":    "0",
			"net.ipv6.conf.all.accept_dad":        "0",
		},
		Init:    &useInit,
		Runtime: c.Runtime(),
	}

	// TODO(Sargun): Add IPv6 address
	ipv4Addr := c.IPv4Address()
	if ipv4Addr != nil {
		hostCfg.ExtraHosts = append(hostCfg.ExtraHosts, fmt.Sprintf("%s:%s", hostname, *ipv4Addr))
	}

	for _, containerName := range volumeContainers {
		log.Infof("Setting up VolumesFrom from container %s", containerName)
		hostCfg.VolumesFrom = append(hostCfg.VolumesFrom, fmt.Sprintf("%s:ro", containerName))
	}
	hostCfg.CgroupParent = r.pidCgroupPath
	r.registerRuntimeCleanup(func() error {
		return cleanupCgroups(r.pidCgroupPath)
	})

	hostCfg.PidsLimit = int64(r.dockerCfg.pidLimit)
	hostCfg.Memory = c.Resources().Mem * MiB
	hostCfg.MemorySwap = 0
	// Limit this to a fairly small number to prevent the containers from ever getting more CPU shares than the system
	// 16 is chosen, because our biggest machines have 32 cores, and the default shares for the root cgroup is 1024,
	// And this means that at minimum the containers should be able to use about 50% of the machine.

	// We still need to scale this by CPU count to not break atlas metrics
	hostCfg.CPUShares = 100 * c.Resources().CPU

	// Maybe set cfs bandwidth has to be called _after_
	maybeSetCFSBandwidth(r.dockerCfg.cfsBandwidthPeriod, c, hostCfg)

	// Always setup tmpfs: it's needed to ensure Metatron credentials don't persist across reboots and for SystemD to work
	hostCfg.Tmpfs = map[string]string{
		"/run": "rw,exec,size=" + defaultRunTmpFsSize,
	}

	if c.IsSystemD() {
		// systemd requires `/run/lock` to be a separate mount from `/run`
		hostCfg.Tmpfs["/run/lock"] = "rw,exec,size=" + defaultRunLockTmpFsSize
	}

	if shmSize := c.ShmSizeMiB(); shmSize != nil {
		hostCfg.ShmSize = int64(*shmSize) * MiB
	}

	if r.storageOptEnabled {
		hostCfg.StorageOpt = map[string]string{
			"size": fmt.Sprintf("%dM", c.Resources().Disk+builtInDiskBuffer+(imageSize/MiB)),
		}
	}

	coreLimit := &units.Ulimit{
		Name: "core",
		Soft: ((c.Resources().Disk * MiB) + 1*GiB),
		Hard: ((c.Resources().Disk * MiB) + 1*GiB),
	}
	hostCfg.Ulimits = []*units.Ulimit{coreLimit}

	// This is just factored out mutation of these objects to make the code cleaner.
	r.setupLogs(c, hostCfg)

	if r.cfg.PrivilegedContainersEnabled {
		// Note: ATM, this is used to enable MCE to use FUSE within a container and
		// is expected to only be used in their account. So these are the only capabilities
		// we allow.
		log.Infof("Enabling privileged access for task %s", c.TaskID())
		hostCfg.CapAdd = append(hostCfg.CapAdd, "SYS_ADMIN")
		hostCfg.Resources.Devices = append(hostCfg.Resources.Devices, container.DeviceMapping{
			PathOnHost:        fuseDev,
			PathInContainer:   fuseDev,
			CgroupPermissions: "rmw",
		})
		// Note: This is only needed in Docker 1.10 and 1.11. In 1.12 the default
		// seccomp profile will automatically adjust based on the capabilities.
		hostCfg.SecurityOpt = append(hostCfg.SecurityOpt, "apparmor:unconfined")
	} else {
		err = setupAdditionalCapabilities(c, hostCfg)
		if err != nil {
			return nil, nil, err
		}
	}

	// label is necessary for metadata proxy compatibility
	if ipv4Addr != nil {
		containerCfg.Labels[runtimeTypes.VPCIPv4Label] = *ipv4Addr // nolint: staticcheck
		containerCfg.Labels[runtimeTypes.NetIPv4Label] = *ipv4Addr
	}

	if r.cfg.UseNewNetworkDriver {
		hostCfg.NetworkMode = container.NetworkMode("none")
	}

	// This must got after all setup
	containerCfg.Env = c.SortedEnvArray()

	return containerCfg, hostCfg, nil
}

func (r *DockerRuntime) setupLogs(c runtimeTypes.Container, hostCfg *container.HostConfig) {
	// TODO(fabio): move this to a daemon-level config
	hostCfg.LogConfig = container.LogConfig{
		Type: "journald",
	}

	t := true
	hostCfg.Init = &t
	socketFileName := tiniSocketFileName(c)

	hostCfg.Binds = append(hostCfg.Binds, r.tiniSocketDir+":/titus-executor-sockets:ro")
	c.SetEnvs(map[string]string{
		"TITUS_REDIRECT_STDERR": "/logs/stderr",
		"TITUS_REDIRECT_STDOUT": "/logs/stdout",
		"TITUS_UNIX_CB_PATH":    filepath.Join("/titus-executor-sockets/", socketFileName),
		/* Require us to send a message to tini in order to let it know we're ready for it to start the container */
		"TITUS_CONFIRM": trueString,
	})

	if r.dockerCfg.tiniVerbosity > 0 {
		c.SetEnv("TINI_VERBOSITY", strconv.Itoa(r.dockerCfg.tiniVerbosity))
	}
}

func (r *DockerRuntime) hostOSPathToTiniSocket(c runtimeTypes.Container) string {
	socketFileName := tiniSocketFileName(c)

	return filepath.Join(r.tiniSocketDir, socketFileName)
}

func tiniSocketFileName(c runtimeTypes.Container) string {
	return fmt.Sprintf("%s.socket", c.TaskID())
}

func netflixLoggerTempDir(cfg config.Config, c runtimeTypes.Container) string {
	return filepath.Join(cfg.LogsTmpDir, c.TaskID())
}

func sleepWithCtx(parentCtx context.Context, d time.Duration) error {
	select {
	case <-parentCtx.Done():
		return parentCtx.Err()
	case <-time.After(d):
		return nil
	}
}

func imageExists(ctx context.Context, client *docker.Client, ref string) (*types.ImageInspect, error) {
	resp, _, err := client.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		if docker.IsErrNotFound(err) {
			return nil, nil
		}

		return nil, err
	}

	log.WithField("imageName", ref).Debugf("Image exists. Response: %+v", resp)
	return &resp, nil
}

// DockerImageRemove removes an image from the docker host
func (r *DockerRuntime) DockerImageRemove(ctx context.Context, imgName string) error {
	_, err := r.client.ImageRemove(ctx, imgName, types.ImageRemoveOptions{})
	if err != nil && strings.Contains(err.Error(), "No such image") {
		return nil
	}

	return err
}

// DockerPull returns an ImageInspect pointer if the image was cached, and we didn't need to pull, nil otherwise
func (r *DockerRuntime) DockerPull(ctx context.Context, c runtimeTypes.Container) (*types.ImageInspect, error) {
	imgName := c.QualifiedImageName()
	logger := log.WithField("imageName", imgName)

	if c.ImageDigest() != nil {
		// Only check for a cached image if a digest was specified: image tags are mutable
		imgInfo, err := imageExists(ctx, r.client, imgName)
		if err != nil {
			logger.WithError(err).Errorf("DockerPull: error inspecting image")

			// Can get "invalid reference format" error: return "not found" to be consistent with pull by tag
			if isBadImageErr(err) {
				return nil, &runtimeTypes.RegistryImageNotFoundError{Reason: err}
			}
			return nil, err
		}

		if imgInfo != nil {
			logger.Info("DockerPull: image exists: not pulling image")
			r.metrics.Counter("titus.executor.dockerImageCachedPulls", 1, nil)
			return imgInfo, nil
		}
	}

	r.metrics.Counter("titus.executor.dockerImagePulls", 1, nil)
	logger.Infof("DockerPull: pulling image")
	pullStartTime := time.Now()
	if err := pullWithRetries(ctx, r.metrics, r.client, c.QualifiedImageName(), doDockerPull); err != nil {
		return nil, err
	}
	r.metrics.Timer("titus.executor.imagePullTime", time.Since(pullStartTime), c.ImageTagForMetrics())
	return nil, nil
}

func vpcToolPath() string {
	myPath := os.Args[0]
	ret, err := filepath.Abs(filepath.Join(filepath.Dir(myPath), "titus-vpc-tool"))
	if err != nil {
		panic(err)
	}
	return ret
}

// Use image labels to determine if the container should be configured to run SystemD
func setSystemdRunning(ctx context.Context, imageInfo types.ImageInspect, c runtimeTypes.Container) error {
	ctx = logger.WithField(ctx, "imageName", c.QualifiedImageName())

	if systemdBool, ok := imageInfo.Config.Labels[systemdImageLabel]; ok {
		logger.G(ctx).WithField("systemdLabel", systemdBool).Info("SystemD image label set")

		val, err := strconv.ParseBool(systemdBool)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Error parsing systemd image label")
			return errors.Wrap(err, "error parsing systemd image label")
		}

		c.SetSystemD(val)
		return nil
	}

	return nil
}

// This will setup c.Allocation
func prepareNetworkDriver(parentCtx context.Context, cfg Config, c runtimeTypes.Container) (cleanupFunc, error) { // nolint: gocyclo
	log.Printf("Configuring VPC network for %s", c.TaskID())

	args := []string{
		"assign",
		"--device-idx", strconv.Itoa(*c.NormalizedENIIndex()),
		"--security-groups", strings.Join(*c.SecurityGroupIDs(), ","),
		"--task-id", c.TaskID(),
	}

	if c.SignedAddressAllocationUUID() != nil {
		args = append(args, "--ipv4-allocation-uuid", *c.SignedAddressAllocationUUID())
	}

	if c.VPCAccountID() != nil {
		args = append(args, "--interface-account", *c.VPCAccountID())
	}

	if c.SubnetIDs() != nil {
		args = append(args, "--subnet-ids", *c.SubnetIDs())
	}

	if c.ElasticIPPool() != nil {
		args = append(args, "--elastic-ip-pool", *c.ElasticIPPool())
	}

	if c.ElasticIPs() != nil {
		args = append(args, "--elastic-ips", *c.ElasticIPs())
	}

	if c.AssignIPv6Address() {
		args = append(args, "--assign-ipv6-address=true")
	}

	if c.UseJumboFrames() {
		args = append(args, "--jumbo=true")
	}

	// We intentionally don't use context here, because context only KILLs.
	// Instead we rely on the idea of the cleanup function below.

	allocationCommand := exec.Command(vpcToolPath(), args...) // nolint: gosec
	allocationCommand.Stderr = os.Stderr
	stdoutPipe, err := allocationCommand.StdoutPipe()
	if err != nil {
		return nil, errors.Wrap(err, "Could not setup stdout pipe for allocation command")
	}

	err = allocationCommand.Start()
	if err != nil {
		return nil, errors.Wrap(err, "Could not start allocation command")
	}

	// errCh
	errCh := make(chan error, 1)

	// if you write to killCh, it will start to try to kill the allocation command
	killCh := make(chan struct{}, 10)

	// doneCh is closed once the allocation command exits
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		errCh <- allocationCommand.Wait()
	}()
	go func() {
		select {
		case <-killCh:
			log.Info("Terminating allocation command")
		case <-doneCh:
			// The command exited, no need to stand at our perch ready to terminate it.
			return
		}
		err2 := allocationCommand.Process.Signal(unix.SIGTERM)
		if err2 != nil {
			log.WithError(err2).Error("Unable to send SIGTERM to allocation command")
		}
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-doneCh:
			// The command successfully exited
			return
		}
		// The timer fired, and it's time to send the kill signal
		log.Warn("Sending kill signal to allocation command")
		err2 = allocationCommand.Process.Kill()
		if err2 != nil {
			log.WithError(err2).Error("Unable to send SIGKILL to allocation command")
		}
	}()

	killTimer := time.AfterFunc(2*time.Minute, func() {
		killCh <- struct{}{}
	})
	var vpcAllocation vpcTypes.HybridAllocation
	err = json.NewDecoder(stdoutPipe).Decode(&vpcAllocation)
	if err != nil {
		log.WithError(err).Error("Unable to read JSON from allocate command")
		return nil, fmt.Errorf("Unable to read json from pipe: %+v", err) // nolint: gosec
	}
	c.SetVPCAllocation(&vpcAllocation)

	if !killTimer.Stop() {
		err = errors.New("Kill timer fired. Race condition")
		log.WithError(err).Error("Accidentally killed the allocation command, leaving us in a 'unknown' state")
		return nil, err
	}

	if !vpcAllocation.Success {
		// Kill the thing
		killCh <- struct{}{}
		log.WithField("error", vpcAllocation.Error).Error("VPC Configuration error")
		if (strings.Contains(vpcAllocation.Error, "invalid security groups requested for vpc id")) ||
			(strings.Contains(vpcAllocation.Error, "InvalidGroup.NotFound") ||
				(strings.Contains(vpcAllocation.Error, "InvalidSecurityGroupID.NotFound")) ||
				(strings.Contains(vpcAllocation.Error, "Security groups not found"))) {
			var invalidSg runtimeTypes.InvalidSecurityGroupError
			invalidSg.Reason = errors.New(vpcAllocation.Error)
			return nil, &invalidSg
		}
		return nil, fmt.Errorf("vpc network configuration error: %s", vpcAllocation.Error)
	}

	if vpcAllocation.Generation == nil {
		err = errors.New("Unable to determine allocation generation")
		log.WithError(err).Warn("Could not process allocation")
		killCh <- struct{}{}
		return nil, err
	}

	switch g := (*vpcAllocation.Generation); g {
	case vpcTypes.V1:
		return func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			killCh <- struct{}{}
			var err2 error
			select {
			case err2 = <-errCh:
			case <-ctx.Done():
				return errors.Wrap(ctx.Err(), "Error waiting for v1 assignment command to exit")
			}
			if err2 != nil {
				log.WithError(err2).Error("Received error on termination of assignment command")
				return errors.Wrap(err2, "Could not unassign task IP address")
			}
			return nil
		}, nil
	case vpcTypes.V3:
		err = <-errCh
		if err != nil {
			return nil, errors.Wrap(err, "Error experienced when running V3 allocate command")
		}
		return func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			unassignCommand := exec.CommandContext(ctx, vpcToolPath(), "unassign", "--task-id", c.TaskID()) // nolint: gosec
			err2 := unassignCommand.Run()
			if err2 != nil {
				log.WithError(err2).Error("Experienced error unassigning v3 allocation")
				return errors.Wrap(err2, "Could not unassign task IP address")
			}
			return nil
		}, nil
	default:
		err = fmt.Errorf("Unknown generation: %s", g)
		killCh <- struct{}{}
		log.WithError(err).Error("Received allocation with unknown generation")
		return nil, err
	}
}

// cleanContainerName creates a "clean" container name that adheres to docker's allowed character list
func cleanContainerName(prefix string, imageName string) string {
	// so we replace @ with - to match Docker's image naming scheme, a la:
	// [a-zA-Z0-9][a-zA-Z0-9_.-]
	noDashes := strings.Replace(imageName, ":", "-", -1)
	noAts := strings.Replace(noDashes, "@", "-", -1)
	noSlashes := strings.Replace(noAts, "/", "_", -1)
	return prefix + "-" + noSlashes
}

// createVolumeContainerFunc returns a function (suitable for running in a Goroutine) that will create a volume container. See createVolumeContainer() below.
func (r *DockerRuntime) createVolumeContainerFunc(sCfg *runtimeTypes.SidecarContainerConfig, containerName *string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		logger.G(ctx).WithField("serviceName", sCfg.ServiceName).Infof("Setting up container")
		cfg := &container.Config{
			Hostname:   fmt.Sprintf("titus-%s", sCfg.ServiceName),
			Volumes:    sCfg.Volumes,
			Entrypoint: []string{"/bin/bash"},
			Image:      sCfg.Image,
		}
		hostConfig := &container.HostConfig{
			NetworkMode: "none",
		}

		createErr := r.createVolumeContainer(ctx, containerName, cfg, hostConfig)
		if createErr != nil {
			return errors.Wrapf(createErr, "Unable to setup %s container", sCfg.ServiceName)
		}

		return nil
	}
}

// createVolumeContainer creates a container to be used as a source for volumes to be mounted via VolumesFrom
func (r *DockerRuntime) createVolumeContainer(ctx context.Context, containerName *string, cfg *container.Config, hostConfig *container.HostConfig) error { // nolint: gocyclo
	image := cfg.Image
	tmpImageInfo, err := imageExists(ctx, r.client, image)
	if err != nil {
		return err
	}

	imageSpecifiedByTag := !strings.Contains(image, "@")
	ctx = logger.WithField(ctx, "hostName", cfg.Hostname)
	ctx = logger.WithField(ctx, "imageName", image)

	if tmpImageInfo == nil || imageSpecifiedByTag {
		logger.G(ctx).WithField("byTag", imageSpecifiedByTag).Info("createVolumeContainer: pulling image")
		err = pullWithRetries(ctx, r.metrics, r.client, image, doDockerPull)
		if err != nil {
			return err
		}
		resp, _, iErr := r.client.ImageInspectWithRaw(ctx, image)
		if iErr != nil {
			return iErr
		}

		// If the image was specified as a tag, resolve it to a digest in case the tag was updated
		image = resp.RepoDigests[0]
		cfg.Image = image
	} else {
		logger.G(ctx).Info("createVolumeContainer: image exists: not pulling image")
	}

	*containerName = cleanContainerName(cfg.Hostname, image)
	ctx = logger.WithField(ctx, "containerName", *containerName)

	// Check if this container exists, if not create it.
	_, err = r.client.ContainerInspect(ctx, *containerName)
	if err == nil {
		logger.G(ctx).Info("createVolumeContainer: container exists: not creating")
		return nil
	}

	if !docker.IsErrNotFound(err) {
		return err
	}

	logger.G(ctx).Info("createVolumeContainer: creating container")
	// We don't check the error here, because there's no way
	// to prevent us from accidentally calling this concurrently
	_, tmpErr := r.client.ContainerCreate(ctx, cfg, hostConfig, nil, *containerName)
	if tmpErr == nil {
		return nil
	}

	// Do this with backoff
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			_, err = r.client.ContainerInspect(ctx, *containerName)
			if err == nil {
				return nil
			}
		case <-ctx.Done():
			return multierror.Append(err, tmpErr, ctx.Err())
		}
	}
}

// Prepare host state (pull image, create fs, create container, etc...) for the container
func (r *DockerRuntime) Prepare(parentCtx context.Context) error { // nolint: gocyclo
	var logViewerContainerName string
	var abmetrixContainerName string
	var metatronContainerName string
	var serviceMeshContainerName string
	var sshdContainerName string
	var volumeContainers []string

	parentCtx = logger.WithField(parentCtx, "taskID", r.c.TaskID())
	logger.G(parentCtx).WithField("prepareTimeout", r.dockerCfg.prepareTimeout).Info("Preparing container")

	ctx, cancel := context.WithTimeout(parentCtx, r.dockerCfg.prepareTimeout)
	defer cancel()

	var (
		containerCreateBody container.ContainerCreateCreatedBody
		myImageInfo         *types.ImageInspect
		dockerCfg           *container.Config
		hostCfg             *container.HostConfig
		sidecarConfigs      map[string]*runtimeTypes.SidecarContainerConfig
		size                int64
	)
	dockerCreateStartTime := time.Now()
	group := groupWithContext(ctx)
	err := r.validateEFSMounts(r.c)
	if err != nil {
		goto error
	}

	sidecarConfigs, err = r.c.SidecarConfigs()
	if err != nil {
		goto error
	}

	group.Go(func(ctx context.Context) error {
		imageInfo, pullErr := r.DockerPull(ctx, r.c)
		if pullErr != nil {
			return pullErr
		}

		if imageInfo == nil {
			inspected, _, inspectErr := r.client.ImageInspectWithRaw(ctx, r.c.QualifiedImageName())
			if inspectErr != nil {
				logger.G(ctx).WithField("imageName", r.c.QualifiedImageName()).WithError(inspectErr).Error("Error inspecting docker image")
				return inspectErr
			}
			imageInfo = &inspected
		}

		size = r.reportDockerImageSizeMetric(r.c, imageInfo)
		if !r.hasEntrypointOrCmd(imageInfo, r.c) {
			return NoEntrypointError
		}

		myImageInfo = imageInfo
		return nil
	})

	if shouldStartMetatronSync(&r.cfg, r.c) {
		group.Go(r.createVolumeContainerFunc(sidecarConfigs[runtimeTypes.SidecarServiceMetatron], &metatronContainerName))
	}

	if r.cfg.ContainerSSHD {
		group.Go(r.createVolumeContainerFunc(sidecarConfigs[runtimeTypes.SidecarServiceSshd], &sshdContainerName))
	}
	if r.cfg.ContainerLogViewer {
		group.Go(r.createVolumeContainerFunc(sidecarConfigs[runtimeTypes.SidecarServiceLogViewer], &logViewerContainerName))
	}

	if shouldStartServiceMesh(&r.cfg, r.c) {
		group.Go(r.createVolumeContainerFunc(sidecarConfigs[runtimeTypes.SidecarServiceServiceMesh], &serviceMeshContainerName))
	}

	if shouldStartAbmetrix(&r.cfg, r.c) {
		group.Go(r.createVolumeContainerFunc(sidecarConfigs[runtimeTypes.SidecarServiceAbMetrix], &abmetrixContainerName))
	}

	if r.cfg.UseNewNetworkDriver {
		group.Go(func(ctx context.Context) error {
			prepareNetworkStartTime := time.Now()
			cf, netErr := prepareNetworkDriver(ctx, r.dockerCfg, r.c)
			if netErr == nil {
				r.metrics.Timer("titus.executor.prepareNetworkTime", time.Since(prepareNetworkStartTime), nil)
				r.registerRuntimeCleanup(cf)
			}
			return netErr
		})
	} else {
		// Don't call out to network driver for local development
		allocation := &vpcTypes.HybridAllocation{
			IPV4Address: &vpcapi.UsableAddress{
				Address: &vpcapi.Address{
					Address: "1.2.3.4",
				},
				PrefixLength: 32,
			},
			DeviceIndex: 1,
			Success:     true,
			Error:       "",
			BranchENIID: "eni-cat-dog",
		}
		r.c.SetVPCAllocation(allocation)
		logger.G(ctx).Info("Mocking networking configuration in dev mode to IP: ", allocation)
	}

	group.Go(r.setupGPU)

	err = group.Wait()
	if err != nil {
		goto error
	}

	if err = setSystemdRunning(ctx, *myImageInfo, r.c); err != nil {
		goto error
	}

	if metatronContainerName != "" {
		volumeContainers = append(volumeContainers, metatronContainerName)
	}
	if sshdContainerName != "" {
		volumeContainers = append(volumeContainers, sshdContainerName)
	}
	if logViewerContainerName != "" {
		volumeContainers = append(volumeContainers, logViewerContainerName)
	}
	if serviceMeshContainerName != "" {
		volumeContainers = append(volumeContainers, serviceMeshContainerName)
	}
	if abmetrixContainerName != "" {
		volumeContainers = append(volumeContainers, abmetrixContainerName)
	}

	dockerCfg, hostCfg, err = r.dockerConfig(r.c, getLXCFsBindMounts(), size, volumeContainers)
	if err != nil {
		goto error
	}

	logger.G(ctx).WithFields(map[string]interface{}{
		"dockerCfg": logger.ShouldJSON(ctx, *dockerCfg),
		"hostCfg":   logger.ShouldJSON(ctx, *hostCfg),
	}).Info("Creating container in docker")

	containerCreateBody, err = r.client.ContainerCreate(ctx, dockerCfg, hostCfg, nil, r.c.TaskID())
	r.c.SetID(containerCreateBody.ID)

	r.metrics.Timer("titus.executor.dockerCreateTime", time.Since(dockerCreateStartTime), r.c.ImageTagForMetrics())
	if docker.IsErrNotFound(err) {
		return &runtimeTypes.RegistryImageNotFoundError{Reason: err}
	}
	if err != nil {
		goto error
	}
	ctx = logger.WithField(ctx, "containerID", r.c.ID())
	logger.G(ctx).Info("Container successfully created")

	err = r.createTitusEnvironmentFile(r.c)
	if err != nil {
		goto error
	}
	logger.G(ctx).Info("Titus environment pushed")

	err = r.createTitusContainerConfigFile(r.c, r.startTime)
	if err != nil {
		goto error
	}
	logger.G(ctx).Info("Titus Configuration pushed")

	err = r.pushEnvironment(r.c, myImageInfo)
	if err != nil {
		goto error
	}
	logger.G(ctx).Info("Titus environment pushed")

error:
	if err != nil {
		log.Error("Unable to create container: ", err)
		r.metrics.Counter("titus.executor.dockerCreateContainerError", 1, nil)
	}
	return err
}

// Creates the file $titusEnvironments/ContainerID.json as a serialized version of the ContainerInfo protobuf struct
// so other systems can load it
func (r *DockerRuntime) createTitusContainerConfigFile(c runtimeTypes.Container, startTime time.Time) error {
	containerConfigFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.json", c.TaskID()))

	cfg, err := runtimeTypes.ContainerConfig(c, startTime)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(containerConfigFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644) // nolint: gosec
	if err != nil {
		return err
	}
	defer shouldClose(f)
	r.registerRuntimeCleanup(func() error {
		return os.Remove(containerConfigFile)
	})

	return json.NewEncoder(f).Encode(cfg)
}

// Creates the file $titusEnvironments/ContainerID.env filled with newline delimited set of environment variables
func (r *DockerRuntime) createTitusEnvironmentFile(c runtimeTypes.Container) error {
	envFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.env", c.TaskID()))
	f, err := os.OpenFile(envFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644) // nolint: gosec
	if err != nil {
		return err
	}
	defer shouldClose(f)
	r.registerRuntimeCleanup(func() error {
		return os.Remove(envFile)
	})

	/* writeTitusEnvironmentFile closes the file for us */
	return writeTitusEnvironmentFile(c.Env(), f)
}

func writeTitusEnvironmentFile(env map[string]string, w io.Writer) error {
	writer := bufio.NewWriter(w)
	for key, val := range env {
		if len(key) == 0 {
			continue
		}
		if !environmentVariableKeyRegexp.MatchString(key) {
			continue
		}

		if _, err := writer.WriteString(fmt.Sprintf("%s=%s\n", key, strconv.QuoteToASCII(val))); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func (r *DockerRuntime) logDir(c runtimeTypes.Container) string {
	return filepath.Join(netflixLoggerTempDir(r.cfg, c), "logs")
}

func (r *DockerRuntime) pushEnvironment(c runtimeTypes.Container, imageInfo *types.ImageInspect) error { // nolint: gocyclo
	var envTemplateBuf, tarBuf bytes.Buffer

	//myImageInfo.Config.Env

	if err := executeEnvFileTemplate(c.Env(), imageInfo, &envTemplateBuf); err != nil {
		return err
	}

	// Create a new tar archive.
	tw := tar.NewWriter(&tarBuf)

	if err := tw.WriteHeader(&tar.Header{
		Name:     "data",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "logs",
		Mode:     0777,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.Fatal(err)
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "titus",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.Fatal(err)
	}

	if r.cfg.ContainerSSHD {
		if err := addContainerSSHDConfig(c, tw, r.cfg); err != nil {
			return err
		}
	}

	for _, efsMount := range c.EfsConfigInfo() {
		mp := filepath.Clean(efsMount.GetMountPoint())
		mp = strings.TrimPrefix(mp, "/")
		if err := tw.WriteHeader(&tar.Header{
			Name:     mp,
			Mode:     0777,
			Typeflag: tar.TypeDir,
		}); err != nil {
			log.Fatal(err)
		}
	}

	path := "etc/profile.d/netflix_environment.sh"
	if version, ok := imageInfo.Config.Labels["nflxenv"]; ok && strings.HasPrefix(version, "1.") {
		path = "etc/nflx/base-environment.d/200titus"
	}

	hdr := &tar.Header{
		Name: path,
		Mode: 0644,
		Size: int64(envTemplateBuf.Len()),
	}

	if err := tw.WriteHeader(hdr); err != nil {
		log.Fatalln(err)
	}
	if _, err := tw.Write(envTemplateBuf.Bytes()); err != nil {
		log.Fatalln(err)
	}
	// Make sure to check the error on Close.

	if err := tw.Close(); err != nil {
		return err
	}

	cco := types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
	}

	return r.client.CopyToContainer(context.TODO(), c.ID(), "/", bytes.NewReader(tarBuf.Bytes()), cco)
}

func maybeConvertIntoBadEntryPointError(err error) error {
	if (strings.Contains(err.Error(), "Container command") && strings.Contains(err.Error(), "not found or does not exist.")) ||
		(strings.Contains(err.Error(), "oci runtime error:") && strings.Contains(err.Error(), "executable file not found in $PATH")) ||
		(strings.Contains(err.Error(), "oci runtime error:") && strings.Contains(err.Error(), "no such file or directory")) {
		return &runtimeTypes.BadEntryPointError{Reason: err}
	}

	return err
}

type readWriteMode int

const (
	rw readWriteMode = iota
	ro
	// Not sure how this makes sense?
	// this will be a noop, and give the user rw
	wo
)

type efsMountInfo struct {
	// fields copied from protobuf:
	efsFsID                    string
	cleanMountPoint            string
	cleanEfsFsRelativeMntPoint string
	readWriteFlags             readWriteMode
	// Derived fields
	// Derived from taking the DNS name of: ${efsFsID}.efs.${REGION}.amazonaws.com
	hostname string
}

func (r *DockerRuntime) processEFSMounts(c runtimeTypes.Container) ([]efsMountInfo, error) {
	efsMountInfos := []efsMountInfo{}
	for _, configInfo := range c.EfsConfigInfo() {
		emi := efsMountInfo{
			efsFsID:                    configInfo.GetEfsFsId(),
			cleanMountPoint:            filepath.Clean(configInfo.GetMountPoint()),
			cleanEfsFsRelativeMntPoint: filepath.Clean(configInfo.GetEfsFsRelativeMntPoint()),
		}

		if emi.cleanEfsFsRelativeMntPoint == "" {
			emi.cleanMountPoint = "/"
		}

		switch configInfo.GetMntPerms() {
		case titus.ContainerInfo_EfsConfigInfo_RW:
			emi.readWriteFlags = rw
		case titus.ContainerInfo_EfsConfigInfo_RO:
			emi.readWriteFlags = ro
		case titus.ContainerInfo_EfsConfigInfo_WO:
			emi.readWriteFlags = wo
		default:
			return nil, fmt.Errorf("Invalid EFS mount (read/write flag): %+v", configInfo)
		}

		if r.awsRegion == "" {
			// We don't validate at client creation time, because we don't get this during testing.
			return nil, errors.New("Could not retrieve EC2 region")
		}
		emi.hostname = fmt.Sprintf("%s.efs.%s.amazonaws.com", emi.efsFsID, r.awsRegion)
		efsMountInfos = append(efsMountInfos, emi)
	}

	return efsMountInfos, nil
}

func (r *DockerRuntime) waitForTini(ctx context.Context, listener *net.UnixListener, efsMountInfos []efsMountInfo, c runtimeTypes.Container) (string, error) {
	// This can block for up to the full ctx timeout
	logDir, containerCred, rootFile, unixConn, err := r.setupPostStartLogDirTini(ctx, listener, c)
	if err != nil {
		return logDir, err
	}

	if len(efsMountInfos) > 0 {
		err = r.setupEFSMounts(ctx, c, rootFile, containerCred, efsMountInfos)
		if err != nil {
			return logDir, err
		}
	}

	err = launchTini(unixConn)
	if err != nil {
		shouldClose(unixConn)
	}
	return logDir, err
}

// Start runs an already created container. A watcher is created that monitors container state. The Status Message Channel is ONLY
// valid if err == nil, otherwise it will block indefinitely.
func (r *DockerRuntime) Start(parentCtx context.Context) (string, *runtimeTypes.Details, <-chan runtimeTypes.StatusMessage, error) {
	ctx, cancel := context.WithTimeout(parentCtx, r.dockerCfg.startTimeout)
	defer cancel()
	var err error
	var listener *net.UnixListener
	var details *runtimeTypes.Details
	statusMessageChan := make(chan runtimeTypes.StatusMessage, 10)

	entry := log.WithField("taskID", r.c.TaskID())
	entry.Info("Starting")
	efsMountInfos, err := r.processEFSMounts(r.c)
	if err != nil {
		return "", nil, statusMessageChan, err
	}

	// This sets up the tini listener. It will autoclose whenever the
	if r.tiniEnabled {
		listener, err = r.setupPreStartTini(ctx, r.c)
		if err != nil {
			return "", nil, statusMessageChan, err
		}
	} else {
		if len(efsMountInfos) > 0 {
			entry.Fatal("Cannot perform EFS mounts without Tini")
		}
		entry.Warning("Starting Without Tini, no logging (globally disabled)")
	}

	dockerStartStartTime := time.Now()
	eventCtx, eventCancel := context.WithCancel(context.Background())
	filters := filters.NewArgs()
	filters.Add("container", r.c.ID())
	filters.Add("type", "container")

	eventOptions := types.EventsOptions{
		Filters: filters,
	}

	// 1. We need to establish a event channel
	eventChan, eventErrChan := r.client.Events(eventCtx, eventOptions)

	err = r.client.ContainerStart(ctx, r.c.ID(), types.ContainerStartOptions{})
	if err != nil {
		entry.Error("Error starting: ", err)
		r.metrics.Counter("titus.executor.dockerStartContainerError", 1, nil)
		// Check if bad entry point and return specific error
		eventCancel()
		return "", nil, statusMessageChan, maybeConvertIntoBadEntryPointError(err)
	}

	r.metrics.Timer("titus.executor.dockerStartTime", time.Since(dockerStartStartTime), r.c.ImageTagForMetrics())

	allocation := r.c.VPCAllocation()
	if allocation == nil || allocation.IPV4Address == nil {
		log.Fatal("IP allocation unset")
	}
	eniID := allocation.BranchENIID
	if eniID == "" {
		eniID = allocation.ENI
	}
	details = &runtimeTypes.Details{
		IPAddresses: map[string]string{
			"nfvpc": allocation.IPV4Address.Address.Address,
		},
		NetworkConfiguration: &runtimeTypes.NetworkConfigurationDetails{
			IsRoutableIP: true,
			IPAddress:    allocation.IPV4Address.Address.Address,
			EniIPAddress: allocation.IPV4Address.Address.Address,
			ResourceID:   fmt.Sprintf("resource-eni-%d", allocation.DeviceIndex-1),
			EniID:        eniID,
		},
	}

	if allocation.IPV6Address != nil && allocation.IPV6Address.Address != nil {
		details.NetworkConfiguration.EniIPv6Address = allocation.IPV6Address.Address.Address
	}

	if r.tiniEnabled {
		logDir, err := r.waitForTini(ctx, listener, efsMountInfos, r.c)
		if err != nil {
			eventCancel()
		} else {
			go r.statusMonitor(eventCancel, r.c, eventChan, eventErrChan, statusMessageChan)
		}
		return logDir, details, statusMessageChan, err
	}

	go r.statusMonitor(eventCancel, r.c, eventChan, eventErrChan, statusMessageChan)
	// We already logged above that we aren't using Tini
	// This means that the log watcher is not started
	return "", details, statusMessageChan, nil
}

func (r *DockerRuntime) statusMonitor(cancel context.CancelFunc, c runtimeTypes.Container, eventChan <-chan events.Message, errChan <-chan error, statusMessageChan chan runtimeTypes.StatusMessage) {
	defer close(statusMessageChan)
	defer cancel()

	// This context should be tied to the lifetime of the container -- it will get significantly less broken
	// when we tear out the launchguard code

	for {
		// 3. If the current state of the container is terminal, send it, and bail
		// 4. Else, keep sending messages until we bail
		select {
		case err := <-errChan:
			log.Fatal("Got error while listening for events, bailing: ", err)
		case event := <-eventChan:
			log.Info("Got event: ", event)
			if handleEvent(c, event, statusMessageChan) {
				log.Info("Terminating docker status monitor")
				return
			}
		}
	}
}

// return true to exit
func handleEvent(c runtimeTypes.Container, message events.Message, statusMessageChan chan runtimeTypes.StatusMessage) bool {
	validateMessage(c, message)
	action := strings.Split(message.Action, " ")[0]
	action = strings.TrimRight(action, ":")
	l := log.WithFields(
		map[string]interface{}{
			"action.prefix": action,
			"action":        message.Action,
			"status":        message.Status,
			"id":            message.ID,
			"from":          message.From,
			"type":          message.Type,
			"actorId":       message.Actor.ID,
		})
	for k, v := range message.Actor.Attributes {
		l = l.WithField(fmt.Sprintf("actor.attributes.%s", k), v)
	}
	l.Info("Processing message")
	switch action {
	case "start":
		statusMessageChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
		}
		return false
	case "die":
		if exitCode := message.Actor.Attributes["exitCode"]; exitCode == "0" {
			statusMessageChan <- runtimeTypes.StatusMessage{
				Status: runtimeTypes.StatusFinished,
			}
		} else {
			statusMessageChan <- runtimeTypes.StatusMessage{
				Status: runtimeTypes.StatusFailed,
				Msg:    fmt.Sprintf("exited with code %s", exitCode),
			}
		}
	case "health_status":
		statusMessageChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    fmt.Sprintf("Docker health status: %s", message.Status),
		}
		return false
	case "kill":
		statusMessageChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusFailed,
			Msg:    fmt.Sprintf("killed with signal %s", message.Actor.Attributes["signal"]),
		}
	case "oom":
		statusMessageChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusFailed,
			Msg:    fmt.Sprintf("%s exited due to OOMKilled", c.TaskID()),
		}
		// Ignore exec events entirely
	case "exec_create", "exec_start", "exec_die":
		return false
	default:
		log.WithField("taskID", c.ID()).Info("Received unexpected event: ", message)
		return false
	}

	return true
}

// The only purpose of this is to test the sanity of our filters, and Docker
func validateMessage(c runtimeTypes.Container, message events.Message) {
	if c.ID() != message.ID {
		panic(fmt.Sprint("c.ID() != message.ID: ", message))
	}
	if message.Type != "container" {
		panic(fmt.Sprint("message.Type != container: ", message))
	}
}

const (
	// MS_RDONLY indicates that mount is read-only
	MS_RDONLY = 1 // nolint: golint
)

func (r *DockerRuntime) setupEFSMounts(parentCtx context.Context, c runtimeTypes.Container, rootFile *os.File, cred *ucred, efsMountInfos []efsMountInfo) error {
	baseMountOptions := []string{"vers=4.1,rsize=1048576,wsize=1048576,timeo=600,retrans=2"}
	for _, efsMountInfo := range efsMountInfos {
		// Todo: Make into a const
		// Although 5 minutes is probably far too much here, this window is okay to be large
		// because the parent window should be greater
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/apps/titus-executor/bin/titus-mount", strconv.Itoa(int(cred.pid))) // nolint: gosec
		flags := 0
		if efsMountInfo.readWriteFlags == ro {
			flags = flags | MS_RDONLY
		}
		mountOptions := append(
			baseMountOptions,
			fmt.Sprintf("fsc=%s", c.TaskID()),
			fmt.Sprintf("source=%s:%s", efsMountInfo.hostname, efsMountInfo.cleanEfsFsRelativeMntPoint),
		)
		cmd.Env = []string{
			fmt.Sprintf("MOUNT_TARGET=%s", efsMountInfo.cleanMountPoint),
			fmt.Sprintf("MOUNT_NFS_HOSTNAME=%s", efsMountInfo.hostname),
			fmt.Sprintf("MOUNT_FLAGS=%d", flags),
			fmt.Sprintf("MOUNT_OPTIONS=%s", strings.Join(mountOptions, ",")),
		}

		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Mount failure: %+v: %s", efsMountInfo, string(stdoutStderr))
		}
		cancel()
	}
	return nil
}

// Setup listener
func (r *DockerRuntime) setupPreStartTini(ctx context.Context, c runtimeTypes.Container) (*net.UnixListener, error) {
	fullSocketFileName := r.hostOSPathToTiniSocket(c)

	l, err := net.Listen("unix", fullSocketFileName)
	if err != nil {
		return nil, err
	}
	unixListener := l.(*net.UnixListener)

	err = os.Chmod(fullSocketFileName, 0777) // nolint: gosec
	if err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		shouldClose(l)
		if ctx.Err() == context.DeadlineExceeded {
			log.WithField("ctxError", ctx.Err()).Error("Tini listener timeout occurred")
		}
	}()

	return unixListener, err
}

func (r *DockerRuntime) setupPostStartLogDirTini(ctx context.Context, l *net.UnixListener, c runtimeTypes.Container) (string, *ucred, *os.File, *net.UnixConn, error) {
	genericConn, err := l.Accept()
	if err != nil {
		if ctx.Err() != nil {
			log.WithField("ctxError", ctx.Err()).Error("Never received connection from container: ", err)
			return "", nil, nil, nil, errors.New("Never received connection from container")
		}
		log.Error("Error receiving connection from container: ", err)
		return "", nil, nil, nil, err
	}

	switch typedConn := genericConn.(type) {
	case (*net.UnixConn):
		logDir, cred, rootFile, err := r.setupPostStartLogDirTiniHandleConnection(ctx, c, typedConn)
		return logDir, cred, rootFile, typedConn, err
	default:
		log.Error("Unknown connection type received: ", genericConn)
		return "", nil, nil, nil, errors.New("Unknown connection type received")
	}
}

func (r *DockerRuntime) setupPostStartLogDirTiniHandleConnection(parentCtx context.Context, c runtimeTypes.Container, unixConn *net.UnixConn) (string, *ucred, *os.File, error) {
	waitForFileDescriptorsCtx, waitForFileDescriptorsCancel := context.WithTimeout(parentCtx, time.Second*15)
	defer waitForFileDescriptorsCancel()

	// We might want to keep this around one day as a way of monitoring the container's health
	// Currently, Tini will leak this FD
	go func() {
		<-waitForFileDescriptorsCtx.Done()
		if waitForFileDescriptorsCtx.Err() == context.DeadlineExceeded {
			shouldClose(unixConn)
		}
	}()

	/* Cred here is a ucred. We have a mimic'd type of unix.Ucred, because it's not available
	 * on darwin. I don't want to stub out this entire method / all of these types on darwin,
	 * so we have this. These are the containers uid / pid / gid from the perspective of the
	 * host namespace.
	 */
	cred, err := getPeerInfo(unixConn)
	if err != nil {
		return "", nil, nil, err

	}
	files, err := fd.Get(unixConn, 1, []string{})
	// When we cann this cancel, we guarantee that the above code finished
	waitForFileDescriptorsCancel()

	if waitForFileDescriptorsCtx.Err() == context.DeadlineExceeded {
		log.Error("Timed out waiting for file desciptors")
		return "", nil, nil, errors.New("Timed out waiting for file desciptors")
	}

	r.registerRuntimeCleanup(func() error {
		shouldClose(unixConn)
		return nil
	})
	if err != nil {
		log.Error("Unable to get FDs from container: ", err)
		return "", nil, nil, err
	}

	rootFile := files[0]
	r.registerRuntimeCleanup(rootFile.Close)

	// r.logDir(c), &cred, rootFile, nil
	err = r.setupPostStartLogDirTiniHandleConnection2(parentCtx, c, cred, rootFile)
	return r.logDir(c), &cred, rootFile, err
}

func (r *DockerRuntime) setupPostStartLogDirTiniHandleConnection2(parentCtx context.Context, c runtimeTypes.Container, cred ucred, rootFile *os.File) error { // nolint: gocyclo
	group, errGroupCtx := errgroup.WithContext(parentCtx)

	// This required (write) access to c.RegisterRuntimeCleanup
	if err := r.mountContainerProcPid1InTitusInits(parentCtx, c, cred); err != nil {
		return err
	}

	if r.cfg.UseNewNetworkDriver && c.VPCAllocation().IPV4Address != nil {
		// This writes to C, and registers runtime cleanup functions, this is a write
		// and it writes to a bunch of pointers

		// afaik, since this is the only one *modifying* data in the container object, we should be okay
		group.Go(func() error {
			cf, err := setupNetworking(r.dockerCfg.burst, c, cred)
			if err == nil {
				r.registerRuntimeCleanup(cf)
			}
			return err
		})
	}

	if r.dockerCfg.enableTitusIsolateBlock {
		group.Go(func() error {
			waitForTitusIsolate(errGroupCtx, c.TaskID(), r.dockerCfg.titusIsolateBlockTime)
			return nil
		})
	}

	if r.dockerCfg.bumpTiniSchedPriority {
		group.Go(func() error {
			return setupScheduler(cred)
		})
	}

	group.Go(func() error {
		return setupOOMAdj(c, cred)
	})

	group.Go(func() error {
		return setCgroupOwnership(parentCtx, c, cred)
	})

	if err := group.Wait(); err != nil {
		return err
	}

	// This cannot be done concurrently, because it requires a call to c.RegisterRuntimeCleanup, which
	// is not protected by a lock
	pid := os.Getpid()
	logsRoot := filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(int(rootFile.Fd())))
	logviewerRoot := netflixLoggerTempDir(r.cfg, c)
	if err := os.Symlink(logsRoot, logviewerRoot); err != nil {
		log.WithError(err).Warning("Unable to setup symlink for logviewer")
		return err
	}

	r.registerRuntimeCleanup(func() error {
		return os.Remove(logviewerRoot)
	})

	if err := setupSystemServices(parentCtx, c, r.cfg, cred); err != nil {
		log.WithError(err).Error("Unable to launch system services")
		return err
	}
	return nil
}

func setupNetworkingArgs(burst bool, c runtimeTypes.Container) []string {
	bw := int64(defaultNetworkBandwidth)
	if bwLim := c.BandwidthLimitMbps(); bwLim != nil && *bwLim != 0 {
		bw = *bwLim * 1000 * 1000
	}

	args := []string{
		"setup-container",
		"--bandwidth", strconv.FormatInt(bw, 10),
		"--netns", "3",
	}
	if burst || c.AllowNetworkBursting() {
		args = append(args, "--burst=true")
	}
	if c.UseJumboFrames() {
		args = append(args, "--jumbo=true")
	}

	return args
}

func setupNetworking(burst bool, c runtimeTypes.Container, cred ucred) (cleanupFunc, error) { // nolint: gocyclo
	log.Info("Setting up container network")
	var result vpcTypes.WiringStatus

	netnsPath := filepath.Join("/proc/", strconv.Itoa(int(cred.pid)), "ns", "net")
	netnsFile, err := os.Open(netnsPath)
	if err != nil {
		return nil, err
	}
	defer shouldClose(netnsFile)

	setupCommand := exec.Command(vpcToolPath(), setupNetworkingArgs(burst, c)...) // nolint: gosec
	stdin, err := setupCommand.StdinPipe()
	if err != nil {
		return nil, err // nolint: vet
	}
	stdout, err := setupCommand.StdoutPipe()
	if err != nil {
		return nil, err
	}

	setupCommand.Stderr = os.Stderr
	setupCommand.ExtraFiles = []*os.File{netnsFile}

	err = setupCommand.Start()
	if err != nil {
		return nil, errors.Wrap(err, "Could not start setup command")
	}
	// errCh
	errCh := make(chan error, 1)

	// if you write to killCh, it will start to try to kill the allocation command
	killCh := make(chan struct{}, 10)

	// doneCh is closed once the allocation command exits
	doneCh := make(chan struct{})
	go func() {
		select {
		case <-killCh:
			log.Info("Terminating setup command")
		case <-doneCh:
			// The command exited, no need to stand at our perch ready to terminate it.
			return
		}
		err2 := setupCommand.Process.Signal(unix.SIGTERM)
		if err2 != nil {
			log.WithError(err2).Error("Unable to send SIGTERM to setup command")
		}
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-doneCh:
			// The command successfully exited
			return
		}
		// The timer fired, and it's time to send the kill signal
		log.Warn("Sending kill signal to setup command")
		err2 = setupCommand.Process.Kill()
		if err2 != nil {
			log.WithError(err2).Error("Unable to send SIGKILL to allocation command")
		}
	}()

	killTimer := time.AfterFunc(2*time.Minute, func() {
		killCh <- struct{}{}
	})

	waitForKill := func() {
		defer close(doneCh)
		errCh <- setupCommand.Wait()
	}

	allocation := *c.VPCAllocation()
	if err := json.NewEncoder(stdin).Encode(allocation); err != nil {
		go waitForKill()
		killCh <- struct{}{}
		return nil, err
	}
	if err := json.NewDecoder(stdout).Decode(&result); err != nil {
		go waitForKill()
		killCh <- struct{}{}
		return nil, fmt.Errorf("Unable to read json from pipe during setup-container: %+v", err)
	}

	go waitForKill()

	if !killTimer.Stop() {
		err = errors.New("Kill timer fired. Race condition")
		log.WithError(err).Error("Accidentally killed the setup command, leaving us in a 'unknown' state")
		return nil, err
	}

	if !result.Success {
		killCh <- struct{}{}
		return nil, fmt.Errorf("Network setup error: %s", result.Error)
	}

	switch g := (*allocation.Generation); g {
	case vpcTypes.V1:
		return func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			killCh <- struct{}{}
			var err2 error
			select {
			case err2 = <-errCh:
			case <-ctx.Done():
				return errors.Wrap(ctx.Err(), "Error waiting for v1 setup command to exit")
			}
			if err2 != nil {
				log.WithError(err2).Error("Received error on termination of setup command")
				return errors.Wrap(err2, "Could not teardown container networking")
			}
			return nil
		}, nil
	case vpcTypes.V3:
		// No one should have read off errCh before us.
		err = <-errCh
		if err != nil {
			killCh <- struct{}{}
			return nil, errors.Wrap(err, "Error experienced when running V3 setup command")
		}
		f2, err := os.Open(netnsPath)
		if err != nil {
			return nil, errors.Wrap(err, "Unable to open container network namespace file")
		}
		return func() error {
			return teardownCommand(f2, allocation)
		}, nil
	default:
		err = fmt.Errorf("Unknown generation: %s", g)
		killCh <- struct{}{}
		log.WithError(err).Error("Received allocation with unknown generation")
		return nil, err
	}

}

func teardownCommand(netnsFile *os.File, allocation vpcTypes.HybridAllocation) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	defer shouldClose(netnsFile)

	teardownCommand := exec.CommandContext(ctx, vpcToolPath(), "teardown-container", "--netns", "3") // nolint: gosec
	stdin, err := teardownCommand.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "Cannot get teardown stdin")
	}
	encoder := json.NewEncoder(stdin)

	teardownCommand.Stdout = os.Stdout
	teardownCommand.Stderr = os.Stderr
	teardownCommand.ExtraFiles = []*os.File{netnsFile}
	err = teardownCommand.Start()
	if err != nil {
		log.WithError(err).Error("Experienced error tearing down container")
		return errors.Wrap(err, "Could not start teardown command")
	}

	err = encoder.Encode(allocation)
	if err != nil {
		return errors.Wrap(err, "Unable to encode allocation for teardown command")
	}

	err = teardownCommand.Wait()
	if err != nil {
		return errors.Wrap(err, "Unable to run teardown command")
	}
	return nil
}

func launchTini(conn *net.UnixConn) error {
	// This should be non-blocking
	_, err := conn.Write([]byte{'L'}) // L is for Launch
	return err
}

func (r *DockerRuntime) setupGPU(ctx context.Context) error {
	resources := r.c.Resources()
	if resources == nil {
		return errMissingResources
	}

	if resources.GPU == 0 {
		return nil
	}
	ctx, span := trace.StartSpan(ctx, "DockerRuntime.setupGPU")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("numGPUs", resources.GPU))
	// Allocate a specific GPU to add to the container
	gpuInfo, err := r.gpuManager.AllocDevices(ctx, int(resources.GPU))
	if err != nil {
		err = fmt.Errorf("Cannot allocate %d requested GPU device: %w", resources.GPU, err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	span.AddAttributes(trace.StringAttribute("gpuDevices", fmt.Sprintf("%v", gpuInfo.Devices())))
	r.c.SetGPUInfo(gpuInfo)
	logger.G(ctx).WithField("numGPUs", resources.GPU).WithField("gpuDevices", gpuInfo.Devices()).Info("Allocated GPUs")
	return nil
}

// Kill uses the Docker API to terminate a container and notifies the VPC driver to tear down its networking
func (r *DockerRuntime) Kill(ctx context.Context) error { // nolint: gocyclo
	logger.G(ctx).Info("Killing task")

	var errs *multierror.Error

	containerStopTimeout := defaultKillWait
	if killWait := r.c.KillWaitSeconds(); killWait != nil && *killWait != 0 {
		containerStopTimeout = time.Second * time.Duration(*killWait)
	}

	if containerJSON, err := r.client.ContainerInspect(context.TODO(), r.c.ID()); docker.IsErrNotFound(err) {
		goto stopped
	} else if err != nil {
		log.Error("Failed to inspect container: ", err)
		errs = multierror.Append(errs, err)
		// There could be a race condition here, where if the container is killed before it is started, it could go into a wonky state
	} else if !containerJSON.State.Running {
		goto stopped
	}

	if err := r.client.ContainerStop(context.TODO(), r.c.ID(), &containerStopTimeout); err != nil {
		r.metrics.Counter("titus.executor.dockerStopContainerError", 1, nil)
		log.Errorf("container %s : stop %v", r.c.TaskID(), err)
		errs = multierror.Append(errs, err)
	} else {
		goto stopped
	}

	if err := r.client.ContainerKill(context.TODO(), r.c.ID(), "SIGKILL"); err != nil {
		r.metrics.Counter("titus.executor.dockerKillContainerError", 1, nil)
		log.Errorf("container %s : kill %v", r.c.TaskID(), err)
		errs = multierror.Append(errs, err)
	}

stopped:

	if gpuInfo := r.c.GPUInfo(); gpuInfo != nil {
		numDealloc := gpuInfo.Deallocate()
		logger.G(ctx).WithField("numDealloc", numDealloc).Info("Deallocated GPU devices for task")
	} else {
		logger.G(ctx).Debug("No GPU devices deallocated")
	}

	return errs.ErrorOrNil()
}

// Cleanup runs the registered callbacks for a container
func (r *DockerRuntime) Cleanup(ctx context.Context) error {
	var errs *multierror.Error

	cro := types.ContainerRemoveOptions{
		RemoveVolumes: true,
		RemoveLinks:   false,
		Force:         true,
	}

	if err := r.client.ContainerRemove(context.TODO(), r.c.ID(), cro); err != nil {
		r.metrics.Counter("titus.executor.dockerRemoveContainerError", 1, nil)
		log.Errorf("Failed to remove container '%s' with ID: %s: %v", r.c.TaskID(), r.c.ID(), err)
		errs = multierror.Append(errs, err)
	}

	r.cleanupFuncLock.Lock()
	defer r.cleanupFuncLock.Unlock()
	for i := len(r.cleanup) - 1; i >= 0; i-- {
		errs = multierror.Append(errs, r.cleanup[i]())
	}

	return errs.ErrorOrNil()
}

// reportDockerImageSizeMetric reports a metric that represents the container image's size
func (r *DockerRuntime) reportDockerImageSizeMetric(c runtimeTypes.Container, imageInfo *types.ImageInspect) int64 {
	// reporting image size in KB
	r.metrics.Gauge("titus.executor.dockerImageSize", int(imageInfo.Size/KB), c.ImageTagForMetrics())
	return imageInfo.Size
}

// hasEntrypointOrCmd checks if the image has a an entrypoint, or if we were passed one
func (r *DockerRuntime) hasEntrypointOrCmd(imageInfo *types.ImageInspect, c runtimeTypes.Container) bool {
	entrypoint, cmd := c.Process()
	return len(entrypoint) > 0 || len(cmd) > 0 || len(imageInfo.Config.Entrypoint) > 0 || len(imageInfo.Config.Cmd) > 0
}

func shouldClose(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Error("Could not close: ", err)
	}
}
