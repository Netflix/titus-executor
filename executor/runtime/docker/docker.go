package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/models"
	"github.com/Netflix/titus-executor/nvidia"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/docker/docker/api/types"
	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/docker/go-units"
	"github.com/ftrvxmtrx/fd"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Netflix/titus-executor/api/netflix/titus"
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
	// MS_RDONLY indicates that mount is read-only
	MS_RDONLY              = 1 // nolint: golint
	mountTimeout           = 5 * time.Minute
	mainContainerName      = "main"
	isTerminalDockerEvent  = true
	nonTerminalDockerEvent = false
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
	tiniSocketDir     string
	storageOptEnabled bool
	pidCgroupPath     string
	cfg               config.Config
	dockerCfg         Config
	defaultBindMounts []string

	// cleanup callbacks that runtime implementations can register to do cleanup
	cleanupFuncLock sync.Mutex
	cleanup         []cleanupFunc

	// To be set when initializing a specific instance of the runtime provider
	c                runtimeTypes.Container
	startTime        time.Time
	gpuManager       runtimeTypes.GPUManager
	volumeContainers []string
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
	ctx, span := trace.StartSpan(ctx, "NewDockerRuntime")
	defer span.End()

	log.Info("New Docker client, to host ", cfg.DockerHost)
	client, err := docker.NewClient(cfg.DockerHost, "1.26", nil, map[string]string{})

	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	info, err := client.Info(ctx)

	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	// We bind-mount tini in as /sbin/docker-init to ensure we can always
	// depend on it being there, regardless of the host docker configuration.
	defaultBindMounts := []string{dockerCfg.tiniPath + ":/sbin/docker-init:ro"}
	defaultBindMounts = append(defaultBindMounts, filepath.Join(cfg.RuntimeDir, "pod.json")+":/titus/run/pod.json:ro")

	pidCgroupPath, err := getOwnCgroup("pids")
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	storageOptEnabled := shouldEnableStorageOpts(info)

	runtimeFunc := func(ctx context.Context, c runtimeTypes.Container, startTime time.Time) (runtimeTypes.Runtime, error) {
		ctx, span := trace.StartSpan(ctx, "NewDockerRuntime")
		defer span.End()

		dockerRuntime := &DockerRuntime{
			pidCgroupPath:     pidCgroupPath,
			metrics:           m,
			registryAuthCfg:   nil, // we don't need registry authentication yet
			client:            client,
			cfg:               cfg,
			dockerCfg:         dockerCfg,
			defaultBindMounts: defaultBindMounts,
			cleanup:           []cleanupFunc{},
			c:                 c,
			startTime:         startTime,
			storageOptEnabled: storageOptEnabled,
		}

		for _, dockerOpt := range dockerOpts {
			err := dockerOpt(ctx, dockerRuntime)
			if err != nil {
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
		}

		if dockerRuntime.gpuManager == nil {
			dockerRuntime.gpuManager, err = nvidia.NewNvidiaInfo(ctx, dockerCfg.nvidiaOciRuntime)
			if err != nil {
				err = fmt.Errorf("GPU Manager unset, failed to initialize default (nvidia) GPU manager: %w", err)
				tracehelpers.SetStatus(err, span)
				return nil, err
			}
		}

		// Don't reference captured error variable from above
		err := setupLoggingInfra(dockerRuntime)
		if err != nil {
			tracehelpers.SetStatus(err, span)
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

func setupLoggingInfra(dockerRuntime *DockerRuntime) error {
	var err error
	var tmpDir = "/var/tmp"
	if runtime.GOOS == "darwin" { //nolint:goconst
		// Darwin (docker for Mac) is a special case, because the default allowed
		// bind mounts only include /tmp/, and not /var/tmp.
		// We set this, even though at this exact moment, unix sockets don't work on docker-for-mac
		tmpDir = "/tmp/"
	}
	dockerRuntime.tiniSocketDir, err = ioutil.TempDir(tmpDir, "titus-executor-sockets")
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
	n, err := rand.Read(ipBuf)
	if err != nil {
		panic(err)
	}
	if n != len(ipBuf) {
		panic(fmt.Sprintf("rand.Read only read %d bytes, not %d bytes", n, len(ipBuf)))
	}
	return net.IP(ipBuf).String()
}
func maybeAddOptimisticDad(sysctl map[string]string) {
	if unix.Access("/proc/sys/net/ipv6/conf/default/use_optimistic", 0) == nil {
		sysctl["net.ipv6.conf.default.use_optimistic"] = "1"
	} else {
		log.Warning("Not enabling use_optimistic")
	}
	if unix.Access("/proc/sys/net/ipv6/conf/default/optimistic_dad", 0) == nil {
		sysctl["net.ipv6.conf.default.optimistic_dad"] = "1"
	} else {
		log.Warning("Not enabling optimistic_dad")
	}
}

func (r *DockerRuntime) computeDNSServers() []string {
	switch r.c.EffectiveNetworkMode() {
	case titus.NetworkConfiguration_Ipv6AndIpv4.String():
		// True dual stack means we should provide both
		return []string{"fd00:ec2::253", "169.254.169.253"}
	case titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String():
		// IPv6 with fallback means we only want v6 resolvers, which reduces
		// the burden on TSA for ipv4 udp traffic
		return []string{"fd00:ec2::253"}
	case titus.NetworkConfiguration_Ipv6Only.String():
		// True ipv6 only means we really can only have a v6
		// resolver
		return []string{"fd00:ec2::253"}
	default:
		// Any other situation means we can return the classic v4 resolver
		return []string{"169.254.169.253"}
	}
}

func (r *DockerRuntime) mainContainerDockerConfig(c runtimeTypes.Container, binds []string, imageSize int64, volumeContainers []string) (*container.Config, *container.HostConfig, error) { // nolint: gocyclo
	// Extract the entrypoint and command from the pod. If either is empty,
	// pass them along and let Docker extract them from the image instead.
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
		DNS:        r.computeDNSServers(),
		Sysctls: map[string]string{
			"net.ipv4.tcp_ecn":                    "1",
			"net.ipv6.conf.all.disable_ipv6":      "0",
			"net.ipv6.conf.default.disable_ipv6":  "0",
			"net.ipv6.conf.lo.disable_ipv6":       "0",
			"net.ipv6.conf.default.stable_secret": stableSecret(), // This is to ensure each container sets their addresses differently
			"net.ipv6.conf.all.use_tempaddr":      "0",
			"net.ipv6.conf.default.use_tempaddr":  "0",

			"net.ipv6.conf.default.accept_ra_pinfo": "0",
		},
		Init:    &useInit,
		Runtime: c.Runtime(),
	}

	maybeAddOptimisticDad(hostCfg.Sysctls)

	ipv4Addr := c.IPv4Address()
	if ipv4Addr != nil {
		hostCfg.ExtraHosts = append(hostCfg.ExtraHosts, fmt.Sprintf("%s:%s", hostname, *ipv4Addr))
	}
	// Only in IPv6-Only modes do we set the extra hosts entry for our v6 address
	if c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6Only.String() || c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String() {
		ipv6Addr := c.IPv6Address()
		if ipv6Addr != nil {
			hostCfg.ExtraHosts = append(hostCfg.ExtraHosts, fmt.Sprintf("%s:%s", hostname, *ipv6Addr))
		}
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
		// Systemd *must* be pid1. Setting this variable instructs tini to exec into systemd so it can be pid 1
		c.SetEnv("TINI_HANDOFF", trueString)
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

	// This must go after all setup
	containerCfg.Env = c.SortedEnvArray()
	containerCfg.Env = append(containerCfg.Env, "TITUS_CONTAINER_NAME=main")

	return containerCfg, hostCfg, nil
}

func (r *DockerRuntime) setupLogs(c runtimeTypes.Container, hostCfg *container.HostConfig) {
	// Only configure journald config journald is available
	if _, journalAvailable := os.LookupEnv("JOURNAL_STREAM"); journalAvailable {
		hostCfg.LogConfig = container.LogConfig{
			Type: "journald",
		}
	}

	t := true
	hostCfg.Init = &t
	socketFileName := tiniSocketFileName(c)

	hostCfg.Binds = append(hostCfg.Binds, r.tiniSocketDir+":/titus-executor-sockets:ro")
	c.SetEnvs(map[string]string{
		"TITUS_REDIRECT_STDERR": "/logs/stderr",
		"TITUS_REDIRECT_STDOUT": "/logs/stdout",
	})
	if runtime.GOOS == "linux" {
		// Only in non-darwin (linux) can bind-mounted unix socket directories work
		// Otherwise these will *not* be set, and tini won't bother to call back
		// on these sockets.
		c.SetEnvs(map[string]string{
			"TITUS_UNIX_CB_PATH": filepath.Join("/titus-executor-sockets/", socketFileName),
			/* Require us to send a message to tini in order to let it know we're ready for it to start the container */
			"TITUS_CONFIRM": trueString,
		})
	}

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
	ctx, span := trace.StartSpan(ctx, "imageExists")
	defer span.End()
	span.AddAttributes(trace.StringAttribute(
		"ref", ref))

	resp, _, err := client.ImageInspectWithRaw(ctx, ref)
	if err != nil {
		if docker.IsErrNotFound(err) {
			span.AddAttributes(trace.BoolAttribute("found", false))
			return nil, nil
		}

		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	span.AddAttributes(trace.BoolAttribute("found", true))

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
	ctx, span := trace.StartSpan(ctx, "DockerPull")
	defer span.End()

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
			tracehelpers.SetStatus(err, span)
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
	if err := pullWithRetries(ctx, r.cfg, r.metrics, r.client, c.QualifiedImageName(), doDockerPull); err != nil {
		tracehelpers.SetStatus(err, span)
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
func prepareNetworkDriver(ctx context.Context, cfg Config, c runtimeTypes.Container) (cleanupFunc, error) { // nolint: gocyclo
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "prepareNetworkDriver")
	defer span.End()

	log.Printf("Configuring VPC network for %s", c.TaskID())

	eniIdx := c.NormalizedENIIndex()
	if eniIdx == nil {
		err := errors.New("could not determine normalized ENI index for container")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	sgIDs := c.SecurityGroupIDs()
	if sgIDs == nil {
		err := errors.New("container is missing security groups")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	bw := int64(defaultNetworkBandwidth)
	if bwLim := c.BandwidthLimitMbps(); bwLim != nil && *bwLim != 0 {
		bw = *bwLim * 1000 * 1000
	}

	args := []string{
		"assign",
		"--device-idx", strconv.Itoa(*eniIdx),
		"--security-groups", strings.Join(*sgIDs, ","),
		"--task-id", c.TaskID(),
		"--bandwidth", strconv.FormatInt(bw, 10),
		"--network-mode", c.EffectiveNetworkMode(), // TODO: Deal with HighScale mode either here, or use the effective mode (which is fallback)
	}

	if c.SignedAddressAllocationUUID() != nil {
		args = append(args, "--ipv4-allocation-uuid", *c.SignedAddressAllocationUUID())
	}

	if c.VPCAccountID() != nil {
		args = append(args, "--interface-account", *c.VPCAccountID())
	}

	if c.SubnetIDs() != nil {
		args = append(args, "--subnet-ids", strings.Join(*c.SubnetIDs(), ","))
	}

	if c.ElasticIPPool() != nil {
		args = append(args, "--elastic-ip-pool", *c.ElasticIPPool())
	}

	if c.ElasticIPs() != nil {
		args = append(args, "--elastic-ips", *c.ElasticIPs())
	}

	if c.UseJumboFrames() {
		args = append(args, "--jumbo=true")
	}

	if c.AllowNetworkBursting() {
		args = append(args, "--burst=true")
	}

	// There's a narrow chance that there's a race here that the context expires, but the assignment has
	// been successful, but we didn't read it. the GC should loop back around and fix it.
	allocationCommand := exec.CommandContext(ctx, vpcToolPath(), args...) // nolint: gosec
	stderrPipe, err := allocationCommand.StderrPipe()
	if err != nil {
		err = fmt.Errorf("Could not setup stderr pipe for allocation command: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	stdoutPipe, err := allocationCommand.StdoutPipe()
	if err != nil {
		err = errors.Wrap(err, "Could not setup stdout pipe for allocation command")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = allocationCommand.Start()
	if err != nil {
		err = errors.Wrap(err, "Could not start allocation command")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	var result vpcapi.VPCToolResult
	var errs *multierror.Error
	data, err := ioutil.ReadAll(stdoutPipe)
	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("Could not read from stdout pipe: %w", err))
	} else {
		err = protojson.Unmarshal(data, &result)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("Could not read / deserialize JSON (%s) from assignment command: %w", string(data), err))
		}
	}
	if errs != nil {
		errs = multierror.Append(errs, allocationCommand.Process.Signal(unix.SIGQUIT))
		data, err = ioutil.ReadAll(stderrPipe)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("Could not read stderr: %w", err))
		} else {
			errs = multierror.Append(errs, fmt.Errorf("Read from stderr: %s", string(data)))
		}
		errs = multierror.Append(errs, allocationCommand.Wait())
		tracehelpers.SetStatus(errs, span)
		return nil, errs
	}
	switch t := result.Result.(type) {
	case *vpcapi.VPCToolResult_Error:
		log.WithField("error", t.Error.Error).Error("VPC Configuration error")
		if (strings.Contains(t.Error.Error, "invalid security groups requested for vpc id")) ||
			(strings.Contains(t.Error.Error, "InvalidGroup.NotFound") ||
				(strings.Contains(t.Error.Error, "InvalidSecurityGroupID.NotFound")) ||
				(strings.Contains(t.Error.Error, "Security groups not found"))) {
			var invalidSg runtimeTypes.InvalidSecurityGroupError
			invalidSg.Reason = errors.New(t.Error.Error)
			return nil, &invalidSg
		}
		err = fmt.Errorf("vpc network configuration error: %s", t.Error.Error)
		tracehelpers.SetStatus(err, span)
		return nil, err
	case *vpcapi.VPCToolResult_Assignment:
		c.SetVPCAllocation(t.Assignment)
	default:
		err = fmt.Errorf("Unknown type: %t", t)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = allocationCommand.Wait()
	if err != nil {
		err = fmt.Errorf("Allocation command exited with unexpected error: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		unassignCommand := exec.CommandContext(ctx, vpcToolPath(), "unassign", "--task-id", c.TaskID()) // nolint: gosec
		err := unassignCommand.Run()
		if err != nil {
			log.WithError(err).Error("Experienced error unassigning v3 allocation")
			return errors.Wrap(err, "Could not unassign task IP address")
		}
		return nil
	}, nil
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
func (r *DockerRuntime) createVolumeContainerFunc(sOpts *runtimeTypes.ServiceOpts) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		logger.G(ctx).WithField("serviceName", sOpts.ServiceName).Infof("Setting up container")
		cfg := &container.Config{
			Hostname:   sOpts.ServiceName,
			Volumes:    sOpts.Volumes,
			Entrypoint: []string{"/bin/bash"},
			Image:      sOpts.Image,
		}
		hostConfig := &container.HostConfig{
			NetworkMode: "none",
		}

		createErr := r.createVolumeContainer(ctx, &sOpts.ContainerName, cfg, hostConfig)
		if createErr != nil {
			if sOpts.Required {
				return errors.Wrapf(createErr, "Unable to setup required %s container '%s'", sOpts.ServiceName, sOpts.ContainerName)
			}
			logger.G(ctx).WithField("serviceName", sOpts.ServiceName).Warnf("Unable to setup optional %s container '%s': %s", sOpts.ServiceName, sOpts.ContainerName, createErr)
			return nil
		}
		return nil
	}
}

// createVolumeContainer creates a container to be used as a source for volumes to be mounted via VolumesFrom
func (r *DockerRuntime) createVolumeContainer(ctx context.Context, containerName *string, cfg *container.Config, hostConfig *container.HostConfig) error { // nolint: gocyclo
	image := cfg.Image
	if image == "" {
		return fmt.Errorf("No image set for %s, can't create a volume container for it", *containerName)
	}
	tmpImageInfo, err := imageExists(ctx, r.client, image)
	if err != nil {
		return err
	}

	imageSpecifiedByTag := !strings.Contains(image, "@")
	ctx = logger.WithField(ctx, "hostName", cfg.Hostname)
	ctx = logger.WithField(ctx, "imageName", image)

	if tmpImageInfo == nil || imageSpecifiedByTag {
		logger.G(ctx).WithField("byTag", imageSpecifiedByTag).Info("createVolumeContainer: pulling image")
		err = pullWithRetries(ctx, r.cfg, r.metrics, r.client, image, doDockerPull)
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

// Prepare host state (pull images, create fs, create container, etc...)
func (r *DockerRuntime) Prepare(ctx context.Context, pod *v1.Pod) error { // nolint: gocyclo
	var volumeContainers []string
	var sharedMountDirs []string

	ctx, cancel := context.WithTimeout(ctx, r.dockerCfg.prepareTimeout)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "Prepare")
	defer span.End()

	ctx = logger.WithField(ctx, "taskID", r.c.TaskID())
	logger.G(ctx).WithField("prepareTimeout", r.dockerCfg.prepareTimeout).Info("Preparing container")

	var (
		containerCreateBody container.ContainerCreateCreatedBody
		myImageInfo         *types.ImageInspect
		dockerCfg           *container.Config
		hostCfg             *container.HostConfig
		systemServices      []*runtimeTypes.ServiceOpts
		size                int64
		runTmpfs            string
		err                 error
	)
	dockerCreateStartTime := time.Now()
	group := groupWithContext(ctx)
	bindMounts := r.defaultBindMounts
	totalExtraContainerCount := len(r.c.ExtraUserContainers()) + len(r.c.ExtraPlatformContainers())

	// In the case where we have multiple containers, we must create a tmps on disk
	// for *all* of them to share. Otherwise, in the simple case where there is only
	// one container, the built-in tmpfs of the one container is enough.
	if len(append(r.c.ExtraPlatformContainers(), r.c.ExtraUserContainers()...)) > 0 {
		runTmpfs, err = r.createMetatronTmpfs()
		r.registerRuntimeCleanup(r.cleanupMetatronTmpfs)
		if err != nil {
			goto error
		}
		bindMounts = append(bindMounts, runTmpfs)
	}

	systemServices, err = r.c.SystemServices()
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

	if totalExtraContainerCount > 0 {
		group.Go(func(ctx context.Context) error {
			logger.G(ctx).Infof("Pulling %d other user/platform containers", totalExtraContainerCount)
			return r.pullAllExtraContainers(ctx, pod)
		})
	}

	for _, sidecarConfig := range systemServices {
		if sidecarConfig.Volumes != nil && sidecarConfig.EnabledCheck != nil && sidecarConfig.EnabledCheck(&r.cfg, r.c) {
			sidecarConfig.ContainerName = sidecarConfig.ServiceName
			group.Go(r.createVolumeContainerFunc(sidecarConfig))
		}
	}

	if runtimeTypes.GetSidecarConfig(systemServices, runtimeTypes.SidecarSeccompAgent).EnabledCheck(&r.cfg, r.c) {
		r.c.SetEnvs(map[string]string{
			"TITUS_SECCOMP_NOTIFY_SOCK_PATH":         filepath.Join("/titus-executor-sockets/", "titus-seccomp-agent.sock"),
			"TITUS_SECCOMP_AGENT_NOTIFY_SOCKET_PATH": filepath.Join(r.tiniSocketDir, "titus-seccomp-agent.sock"),
		})
		if r.c.SeccompAgentEnabledForPerfSyscalls() {
			r.c.SetEnvs(map[string]string{
				"TITUS_SECCOMP_AGENT_HANDLE_PERF_SYSCALLS": "true",
			})
		}
		if r.c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String() {
			r.c.SetEnvs(map[string]string{
				"TITUS_SECCOMP_AGENT_HANDLE_NET_SYSCALLS": "true",
			})
		}
	}

	if runtimeTypes.GetSidecarConfig(systemServices, runtimeTypes.SidecarTitusStorage).EnabledCheck(&r.cfg, r.c) {
		v := r.c.EBSInfo()
		r.c.SetEnvs(map[string]string{
			"TITUS_EBS_VOLUME_ID":   v.VolumeID,
			"TITUS_EBS_MOUNT_POINT": v.MountPath,
			"TITUS_EBS_MOUNT_PERM":  v.MountPerm,
			"TITUS_EBS_FSTYPE":      v.FSType,
		})
	}

	if runtimeTypes.GetSidecarConfig(systemServices, runtimeTypes.SidecarTrafficSteering).EnabledCheck(&r.cfg, r.c) {
		if r.c.TrafficSteeringEnabled() {
			r.c.SetEnvs(map[string]string{
				"TITUS_SECCOMP_AGENT_HANDLE_TRAFFIC_STEERING": "true",
			})
		}
	}

	if r.cfg.UseNewNetworkDriver {
		group.Go(func(ctx context.Context) error {
			prepareNetworkStartTime := time.Now()
			cf, netErr := prepareNetworkDriver(ctx, r.dockerCfg, r.c)
			if netErr == nil {
				r.metrics.Timer("titus.executor.prepareNetworkTime", time.Since(prepareNetworkStartTime), nil)
				r.registerRuntimeCleanup(cf)
			}
			tracehelpers.SetStatus(netErr, span)
			return netErr
		})
	} else {
		// Don't call out to network driver for local development
		allocation := &vpcapi.Assignment{
			Assignment: &vpcapi.Assignment_AssignIPResponseV3{
				AssignIPResponseV3: &vpcapi.AssignIPResponseV3{
					Ipv4Address: &vpcapi.UsableAddress{
						Address: &vpcapi.Address{
							Address: "192.0.2.1",
						},
						PrefixLength: 32,
					},
					Ipv6Address: nil,
					BranchNetworkInterface: &vpcapi.NetworkInterface{
						NetworkInterfaceId: "eni-cat-dog",
					},
					TrunkNetworkInterface: nil,
					VlanId:                1,
					ElasticAddress: &vpcapi.ElasticAddress{
						Ip: "203.0.113.11",
					},
					ClassId:   0,
					Routes:    nil,
					Bandwidth: nil,
				},
			},
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

	for _, sidecarConfig := range systemServices {
		if sidecarConfig.ContainerName == "" {
			// This indicates that the systemService doesn't have a container at all,
			// and should not assume it has a volume container
			continue
		} else if sidecarConfig.ContainerName == sidecarConfig.ServiceName {
			// If the ContainerName is still just ServiceName, that indicates it has not be initialized yet,
			// probably because if failed to be pulled, potentically indicating that the image doesn't exist,
			// or a bad deploy, or heck just a typo in the name or something
			if sidecarConfig.Required {
				err = fmt.Errorf("Unable to get volume container of required sidecar %s", sidecarConfig.ServiceName)
				goto error
			} else {
				// If the ContainerName is still uninitialized, but this service is not required, then it is
				// ok to just log about it, but it should not be included on the list of volume containers to use
				// (because it doesn't exist)
				logger.G(ctx).Warnf("Skipping volume container of optional sidecar %s", sidecarConfig.ServiceName)
			}
		} else {
			volumeContainers = append(volumeContainers, sidecarConfig.ContainerName)
		}
	}
	r.volumeContainers = volumeContainers

	bindMounts = append(bindMounts, getLXCFsBindMounts()...)
	if r.c.SeccompAgentEnabledForPerfSyscalls() {
		bindMounts = append(bindMounts, getKernelBindMounts()...)
	}

	dockerCfg, hostCfg, err = r.mainContainerDockerConfig(r.c, bindMounts, size, volumeContainers)
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
	logger.G(ctx).Info("Titus environment file created")

	err = r.createTitusContainerInfoFile(ctx, r.c, r.startTime)
	if err != nil {
		goto error
	}
	logger.G(ctx).Info("Titus cInfo file created")

	sharedMountDirs = getSharedMountDirsFromPod(pod)
	err = r.pushEnvironment(ctx, r.c, myImageInfo, sharedMountDirs)
	if err != nil {
		goto error
	}
	logger.G(ctx).Info("Titus environment pushed")

error:
	if err != nil {
		tracehelpers.SetStatus(err, span)
		log.Error("Unable to create main container: ", err)
		r.metrics.Counter("titus.executor.dockerCreateContainerError", 1, nil)
	}
	return err
}

// getSharedMountDirsFromPod takes a pod and looks for special SharedVolumeMounts for the main container.
// We must get this list first, and ensure these directories exists for inside the container so that the
// actual bind mount will work.
// Note that this does not support sharing volumes from a source other than the 'main' container.
func getSharedMountDirsFromPod(pod *v1.Pod) []string {
	sharedMountDirs := []string{}
	for _, v := range pod.Spec.Volumes {
		if v.FlexVolume != nil && v.FlexVolume.Driver == "SharedContainerVolumeSource" && v.FlexVolume.Options != nil {
			if v.FlexVolume.Options["sourceContainer"] == "main" {
				sharedMountDirs = append(sharedMountDirs, v.FlexVolume.Options["sourcePath"])
			}
		}
	}
	return sharedMountDirs
}

// Creates the file $titusEnvironments/ContainerID.json as a serialized version of the ContainerInfo protobuf struct
// so other systems can load it
func (r *DockerRuntime) createTitusContainerInfoFile(ctx context.Context, c runtimeTypes.Container, startTime time.Time) error {
	containerConfigFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.json", c.TaskID()))

	cfg, err := runtimeTypes.GenerateSyntheticContainerInfoPass2(c, startTime)
	if err != nil {
		return err
	}

	logger.G(ctx).WithField("containerCfg", logger.ShouldJSON(ctx, cfg)).Debug("writing container config")
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

func getUnameR() (string, error) {
	var uts unix.Utsname
	err := unix.Uname(&uts)
	if err != nil {
		return "", err
	}
	// Calling the syscall gives us a very raw null-terminated
	// byte array. We need to find the null and only slice up
	// that part
	n := bytes.IndexByte(uts.Release[:], 0)
	return string(uts.Release[:n]), nil
}

func getKernelBindMounts() []string {
	mounts := []string{
		"/boot:/boot:ro",
		"/lib/modules:/lib/modules:ro",
	}
	unameR, err := getUnameR()
	if err == nil {
		kernelHeaders := fmt.Sprintf("/usr/src/linux-headers-%s:/usr/src/linux-headers-%s:ro", unameR, unameR)
		mounts = append(mounts, kernelHeaders)
	}
	return mounts
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

// createMetatronTmpfs creates a tmpfs directory outside of the container(s) for use for '/run' and other
// tmp directires. this is desirable so that secrets in /run are not persisted to disk.
// We don't use the native docker tmpfs functionality, because we want to be able to
// share this volume between containers in a pod, just like kubelet does
func (r *DockerRuntime) createMetatronTmpfs() (string, error) {
	podMetatronFsHostPath, err := r.getPodMetatronFsHostPath()
	if err != nil {
		return "", err
	}
	err = os.MkdirAll(podMetatronFsHostPath, os.FileMode(0755))
	if err != nil {
		return "", err
	}
	err = os.Chmod(podMetatronFsHostPath, os.FileMode(0755))
	if err != nil {
		return "", err
	}
	err = mountTmpfs(podMetatronFsHostPath, defaultRunTmpFsSize)
	v := podMetatronFsHostPath + ":/run/metatron:rw"
	return v, err
}

func (r *DockerRuntime) cleanupMetatronTmpfs() error {
	podMetatronFsHostPath, err := r.getPodMetatronFsHostPath()
	if err != nil {
		return err
	}
	return unmountTmpfs(podMetatronFsHostPath)
}

func (r *DockerRuntime) getPodMetatronFsHostPath() (string, error) {
	if r.cfg.RuntimeDir == "" {
		return "", fmt.Errorf("RuntimeDir not set, unable to create tmpfs for /run/metatron")
	}
	hostPath := path.Join(r.cfg.RuntimeDir, "/mounts/run/metatron")
	return hostPath, nil
}

func (r *DockerRuntime) logDir(c runtimeTypes.Container) string {
	return filepath.Join(netflixLoggerTempDir(r.cfg, c), "logs")
}

func (r *DockerRuntime) pushEnvironment(ctx context.Context, c runtimeTypes.Container, imageInfo *types.ImageInspect, sharedMountDirs []string) error { // nolint: gocyclo
	var envTemplateBuf, tarBuf bytes.Buffer

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
		log.WithError(err).Fatal()
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "logs",
		Mode:     0777,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.WithError(err).Fatal()
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "/run-shared",
		Mode:     0777,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.WithError(err).Fatal()
	}

	for _, d := range sharedMountDirs {
		if err := tw.WriteHeader(&tar.Header{
			Name:     d,
			Mode:     0777,
			Typeflag: tar.TypeDir,
		}); err != nil {
			log.WithError(err).Fatal()
		}
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "titus",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.WithError(err).Fatal()
	}

	if err := tw.WriteHeader(&tar.Header{
		Name:     "titus/etc",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		log.WithError(err).Fatal()
	}

	if r.cfg.MetatronEnabled {
		// `/metatron` is a shared folder between all containers in a pod, but it must exist first
		// so that it can be shared
		if err := tw.WriteHeader(&tar.Header{
			Name:     "metatron",
			Mode:     0755,
			Typeflag: tar.TypeDir,
		}); err != nil {
			log.WithError(err).Fatal()
		}
	}

	if r.cfg.ContainerSSHD {
		if err := addContainerSSHDConfig(c, tw, r.cfg); err != nil {
			return err
		}
	}

	for _, nfsMount := range c.NFSMounts() {
		mp := strings.TrimPrefix(nfsMount.MountPoint, "/")
		if err := tw.WriteHeader(&tar.Header{
			Name:     mp,
			Mode:     0777,
			Typeflag: tar.TypeDir,
		}); err != nil {
			log.WithError(err).Fatal()
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
		log.WithError(err).Fatal()
	}
	if _, err := tw.Write(envTemplateBuf.Bytes()); err != nil {
		log.WithError(err).Fatal()
	}
	// Make sure to check the error on Close.

	if err := tw.Close(); err != nil {
		return err
	}

	cco := types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
	}

	return r.client.CopyToContainer(ctx, c.ID(), "/", bytes.NewReader(tarBuf.Bytes()), cco)
}

func maybeConvertIntoBadEntryPointError(err error) error {
	if (strings.Contains(err.Error(), "Container command") && strings.Contains(err.Error(), "not found or does not exist.")) ||
		(strings.Contains(err.Error(), "oci runtime error:") && strings.Contains(err.Error(), "executable file not found in $PATH")) ||
		(strings.Contains(err.Error(), "oci runtime error:") && strings.Contains(err.Error(), "no such file or directory")) {
		return &runtimeTypes.BadEntryPointError{Reason: err}
	}

	return err
}

// setupTini connects to tini, and also sets up NFS mounts
// it does *not* send the L (launch) signal to tini though
func (r *DockerRuntime) setupTini(ctx context.Context, listener *net.UnixListener, c runtimeTypes.Container) (string, *net.UnixConn, error) {
	// This can block for up to the full ctx timeout
	logDir, containerCred, rootFile, unixConn, err := r.setupPostStartLogDirTini(ctx, listener, c)
	if err != nil {
		return logDir, unixConn, err
	}

	if len(c.NFSMounts()) > 0 {
		err = r.setupEFSMounts(ctx, c, rootFile, containerCred)
		if err != nil {
			return logDir, unixConn, err
		}
	}
	return logDir, unixConn, err
}

// Start runs an already created container. A watcher is created that monitors container state. The Status Message Channel is ONLY
// valid if err == nil, otherwise it will block indefinitely.
func (r *DockerRuntime) Start(parentCtx context.Context, pod *v1.Pod) (string, *runtimeTypes.Details, <-chan runtimeTypes.StatusMessage, error) {
	ctx, cancel := context.WithTimeout(parentCtx, r.dockerCfg.startTimeout)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "Start")
	defer span.End()

	var err error
	var listener *net.UnixListener
	var details *runtimeTypes.Details
	statusMessageChan := make(chan runtimeTypes.StatusMessage, 10)

	entry := log.WithField("taskID", r.c.TaskID())
	entry.Info("Starting")
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return "", nil, statusMessageChan, err
	}

	// This sets up the tini listener and pauses the workload
	listener, err = r.setupPreStartTini(ctx, r.c)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return "", nil, statusMessageChan, err
	}

	dockerStartStartTime := time.Now()

	eventCtx, eventCancel := context.WithCancel(context.Background())
	eventCtx = trace.NewContext(eventCtx, span)

	// 1. We need to establish a docker events channel, one for the whole, but it monitors the main container.
	eventChan, eventErrChan := r.getDockerEventsChannelsForContainers(eventCtx, []string{r.c.ID()})

	err = r.client.ContainerStart(ctx, r.c.ID(), types.ContainerStartOptions{})
	if err != nil {
		entry.WithError(err).Error("error starting")
		r.metrics.Counter("titus.executor.dockerStartContainerError", 1, nil)
		// Check if bad entry point and return specific error
		eventCancel()
		err = maybeConvertIntoBadEntryPointError(err)
		tracehelpers.SetStatus(err, span)
		return "", nil, statusMessageChan, err
	}

	r.metrics.Timer("titus.executor.dockerStartTime", time.Since(dockerStartStartTime), r.c.ImageTagForMetrics())

	allocation := r.c.VPCAllocation()
	eni := allocation.ContainerENI()
	if allocation == nil || eni == nil {
		eventCancel()
		if allocation == nil {
			return "", nil, statusMessageChan, errors.New("allocation unset")
		}
		if eni == nil {
			return "", nil, statusMessageChan, errors.New("ENI in allocation unset")
		}
	}

	details = &runtimeTypes.Details{
		NetworkConfiguration: &runtimeTypes.NetworkConfigurationDetails{
			IsRoutableIP: true,
			NetworkMode:  r.c.EffectiveNetworkMode(),
			ResourceID:   fmt.Sprintf("resource-eni-%d", allocation.DeviceIndex()-1),
			EniID:        eni.NetworkInterfaceId,
		},
	}

	if a := allocation.IPV4Address(); a != nil {
		details.NetworkConfiguration.IPAddress = a.Address.Address
		details.NetworkConfiguration.EniIPAddress = a.Address.Address
	}

	if a := allocation.IPV6Address(); a != nil {
		details.NetworkConfiguration.EniIPv6Address = a.Address.Address
	}

	if e := allocation.ElasticAddress(); e != nil {
		details.NetworkConfiguration.ElasticIPAddress = e.Ip
	}

	logDir, tiniConn, err := r.setupTini(ctx, listener, r.c)
	if err != nil {
		eventCancel()
		err = fmt.Errorf("container prestart error: %w", err)
		return "", nil, statusMessageChan, err
	}
	entry.Debugf("Adding status monitor for main container (cid %s)", r.c.ID())
	go r.statusMonitor(eventCancel, r.c.ID(), eventChan, eventErrChan, statusMessageChan)

	inspectOutput, err := r.client.ContainerInspect(ctx, r.c.ID())
	if err != nil {
		eventCancel()
		err = fmt.Errorf("container prestart error inspecting main container: %w", err)
		return "", nil, statusMessageChan, err
	}
	mainContainerRoot := getMainContainerRoot(inspectOutput)

	allOtherContainerIDs := r.getExtraContainerIDs()
	if len(allOtherContainerIDs) > 0 {
		err = r.createOtherContainers(ctx, pod, r.c.ID(), tiniConn, mainContainerRoot)
		if err != nil {
			eventCancel()
			return "", nil, statusMessageChan, err
		}
		// This second docker events channel is for the extra containers, and only exists if we have other containers
		// to work with. This allows the main container channed (created way earliar) to start and watch way before
		// the sidecar containers even exist.
		eventChanExtra, eventErrChanExtra := r.getDockerEventsChannelsForContainers(eventCtx, allOtherContainerIDs)
		for _, c := range r.c.ExtraPlatformContainers() {
			entry.Debugf("Adding status monitor for %s container (cid %s)", c.Name, c.Status.ContainerID)
			go r.statusMonitor(eventCancel, c.Status.ContainerID, eventChanExtra, eventErrChanExtra, statusMessageChan)
		}
		entry.Infof("Starting %d platform sidecars: %v", len(r.getPlaformContainerNames()), r.getPlaformContainerNames())
		err = r.startPlatformDefinedContainers(ctx)
		if err != nil {
			eventCancel()
			return "", nil, statusMessageChan, fmt.Errorf("Failed to start a platform-sidecar container: %s", err)
		}
		entry.Infof("Starting %d user-defined containers: %v", len(r.getUserContainerNames()), r.getUserContainerNames())
		for _, c := range r.c.ExtraUserContainers() {
			entry.Debugf("Adding status monitor for %s container (cid %s)", c.Name, c.Status.ContainerID)
			go r.statusMonitor(eventCancel, c.Status.ContainerID, eventChanExtra, eventErrChanExtra, statusMessageChan)
		}
	}

	// Last, we actually start the containers. And by start we mean:
	// platform sidecars first (via docker start)
	// user extra containers second (via docker start)
	// main container (via tini)
	err = r.startUserDefinedContainers(ctx, tiniConn)
	if err != nil {
		eventCancel()
		return "", nil, statusMessageChan, fmt.Errorf("Failed to start a user-defined container: %s", err)
	}

	return logDir, details, statusMessageChan, err
}

func (r *DockerRuntime) getDockerEventsChannelsForContainers(eventCtx context.Context, containerIDs []string) (<-chan events.Message, <-chan error) {
	filters := filters.NewArgs()
	filters.Add("type", "container")
	for _, containerID := range containerIDs {
		filters.Add("container", containerID)
	}
	eventOptions := types.EventsOptions{
		Filters: filters,
	}
	return r.client.Events(eventCtx, eventOptions)
}

// getMainContainerRoot returns the absolute path of the root of the filesystem of the
// main container (or any container really). Only works on overlay2 storage drivers, returns ""
// otherwise.
func getMainContainerRoot(inspectOutput types.ContainerJSON) string {
	driver := inspectOutput.GraphDriver.Name
	if driver != "overlay2" {
		// Only overlay2 can do mounted volumes like this, other storage drivers
		// don't allow you to "just" get another container's root and mount it somewhere else
		return ""
	}
	return inspectOutput.GraphDriver.Data["MergedDir"]
}

func (r *DockerRuntime) getExtraContainerIDs() []string {
	ids := []string{}
	for _, c := range r.c.ExtraPlatformContainers() {
		ids = append(ids, c.Status.ContainerID)
	}
	for _, c := range r.c.ExtraUserContainers() {
		ids = append(ids, c.Status.ContainerID)
	}
	return ids
}

func (r *DockerRuntime) statusMonitor(cancel context.CancelFunc, containerID string, eventChan <-chan events.Message, errChan <-chan error, statusMessageChan chan runtimeTypes.StatusMessage) {
	for {
		// 3. If the current state of the container is terminal, send it, and bail
		// 4. Else, keep sending messages until we bail
		select {
		case err := <-errChan:
			if errors.Is(err, context.Canceled) {
				return
			}
			log.WithError(err).Errorf("Got unexpected error while listening for docker events for %s, bailing: %s", containerID, err)
			return
		case event := <-eventChan:
			log.Debug("Got docker event: ", event)
			isTerminalEvent := r.handleDockerEvent(event, statusMessageChan)
			if isTerminalEvent {
				cName, err := r.getContainerNameFromID(containerID)
				if err == nil {
					log.WithField("container_name", cName).Infof("Closing docker status monitor for %s because terminal docker event received", cName)
				} else {
					log.WithError(err).Error("Closing docker status monitor, encountered an error looking up the container name")
				}
				return
			}
		}
	}
}

// createOtherContainers launches the other user containers, only looking
// any container objects in the pod *after* the first one, converting the
// v1.Container spec into something docker can understand, and then
// running that container.
func (r *DockerRuntime) createOtherContainers(ctx context.Context, pod *v1.Pod, mainContainerID string, tiniConn *net.UnixConn, mainContainerRoot string) error {
	l := log.WithField("taskID", r.c.TaskID())
	// For speed, we create other containers in parallel
	totalExtraContainerCount := len(r.c.ExtraUserContainers()) + len(r.c.ExtraPlatformContainers())
	if totalExtraContainerCount > 0 {
		l.Infof("Creating %d other user/platform containers", totalExtraContainerCount)
		err := r.createAllExtraContainers(ctx, pod, r.c.ID(), mainContainerRoot)
		if err != nil {
			return fmt.Errorf("Failed to create a user/platform container: %s", err)
		}
	}
	l.Debug("Finished creating (but not starting yet) user/platform containers")
	return nil
}

func (r *DockerRuntime) pullAllExtraContainers(ctx context.Context, pod *v1.Pod) error {
	l := log.WithField("taskID", r.c.TaskID())
	// In this design, the first container has already been pulled, so we only look
	// at the other containers here.
	// It is important to not only pull, but also save a `docker image inspect` on the image
	// we just pulled for later use.
	otherUserContainers := append(r.c.ExtraUserContainers(), r.c.ExtraPlatformContainers()...)
	group := groupWithContext(ctx)
	for _, c := range otherUserContainers {
		c2 := c
		group.Go(func(ctx context.Context) error {
			image := c2.V1Container.Image
			l.Debugf("pulling other container image %s", image)
			err := pullWithRetries(ctx, r.cfg, r.metrics, r.client, image, doDockerPull)
			if err != nil {
				return err
			}
			imageInspect, err2 := imageExists(ctx, r.client, image)
			if err2 != nil {
				return fmt.Errorf("Failed to inspect %s after pull: %w", image, err2)
			}
			c2.ImageInspect = imageInspect
			return nil
		})
	}
	return group.Wait()
}

// createAllExtraContainers *creates* the other user containers,
// except for the 'main' one, which is assumed to be already created
// to store all the linux namespaces
func (r *DockerRuntime) createAllExtraContainers(ctx context.Context, pod *v1.Pod, mainContainerID string, mainContainerRoot string) error {
	l := log.WithField("taskID", r.c.TaskID())
	// With this design, the first container is already created and ready for us
	// to link to (mainContainerID), so we only look at 1+ containers to create
	group := groupWithContext(ctx)
	// We *creating* (not starting) the containers in parallel for speed
	for idx := range r.c.ExtraUserContainers() {
		c := r.c.ExtraUserContainers()[idx]
		group.Go(func(ctx context.Context) error {
			cid, err := r.createExtraContainerInDocker(ctx, c, mainContainerID, mainContainerRoot, pod)
			if err != nil {
				return fmt.Errorf("Failed to create %s user container: %w", c.Name, err)
			}
			c.Status.ContainerID = cid
			c.Status.State = v1.ContainerState{Waiting: &v1.ContainerStateWaiting{Reason: "User Container created. Waiting to start."}}
			c.Status.Image = c.ImageInspect.RepoDigests[0]
			l.Debugf("Created %s, CID: %s", c.Name, cid)
			return nil
		})
	}
	for idx := range r.c.ExtraPlatformContainers() {
		c := r.c.ExtraPlatformContainers()[idx]
		group.Go(func(ctx context.Context) error {
			cid, err := r.createExtraContainerInDocker(ctx, c, mainContainerID, mainContainerRoot, pod)
			if err != nil {
				return fmt.Errorf("Failed to create %s platform container: %w", c.Name, err)
			}
			c.Status.ContainerID = cid
			c.Status.State = v1.ContainerState{Waiting: &v1.ContainerStateWaiting{Reason: "Platform Container created. Waiting to start."}}
			c.Status.Image = c.ImageInspect.RepoDigests[0]
			l.Debugf("Created %s, CID: %s", c.Name, cid)
			return nil
		})
	}
	return group.Wait()
}

func (r *DockerRuntime) startPlatformDefinedContainers(ctx context.Context) error {
	l := log.WithField("taskID", r.c.TaskID())
	group := groupWithContext(ctx)
	for _, c := range r.c.ExtraPlatformContainers() {
		container := c
		group.Go(func(ctx context.Context) error {
			l.Debugf("Starting up platform-defined container %s, container id %s", container.Name, container.Status.ContainerID)
			err := r.client.ContainerStart(ctx, container.Status.ContainerID, types.ContainerStartOptions{})
			if err != nil {
				return fmt.Errorf("Failed to start %s platform container: %w", container.Status.ContainerID, err)
			}
			// TODO: Only set this as started once the healthcheck passes
			container.Status.Started = runtimeTypes.BoolPtr(true)
			// TODO: Only set this as started once the healthcheck passes, even though we don't have a concept of readiness probes
			container.Status.Ready = true
			container.Status.State = v1.ContainerState{Running: &v1.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}}}
			return nil
		})
	}
	return group.Wait()
}

// startUserDefinedContainers starts all existing (pre-created) containers, even the 'main' one (via tini)
func (r *DockerRuntime) startUserDefinedContainers(ctx context.Context, tiniConn *net.UnixConn) error {
	l := log.WithField("taskID", r.c.TaskID())
	group := groupWithContext(ctx)
	for _, c := range r.c.ExtraUserContainers() {
		container := c
		if container.Status.ContainerID == "" {
			return fmt.Errorf("No container id availble. Did it get created in docker?")
		}
		group.Go(func(ctx context.Context) error {
			l.Debugf("Starting up user-defined container %s, container id %s", container.Name, container.Status.ContainerID)
			err := r.client.ContainerStart(ctx, container.Status.ContainerID, types.ContainerStartOptions{})
			if err != nil {
				return fmt.Errorf("Failed to start %s user container: %w", container.Name, err)
			}
			// TODO: Only set this as started once the healthcheck passes
			container.Status.Started = runtimeTypes.BoolPtr(true)
			// TODO: Only set this as started once the healthcheck passes, even though we don't have a concept of readiness probes
			container.Status.Ready = true
			container.Status.State = v1.ContainerState{Running: &v1.ContainerStateRunning{StartedAt: metav1.Time{Time: time.Now()}}}
			return nil
		})
	}

	group.Go(func(ctx context.Context) error {
		// And then lastly we tell tini to launch the main container
		l.Debug("Telling tini to launch the main container")
		err := tellTiniToLaunch(tiniConn)
		if err != nil {
			shouldClose(tiniConn)
			return fmt.Errorf("error launching tini: %w", err)
		}
		return nil
	})
	return group.Wait()
}

func (r *DockerRuntime) createExtraContainerInDocker(ctx context.Context, c *runtimeTypes.ExtraContainer, mainContainerID string, mainContainerRoot string, pod *v1.Pod) (string, error) {
	l := log.WithField("taskID", r.c.TaskID())
	containerName := r.c.TaskID() + "-" + c.Name
	dockerContainerConfig, dockerHostConfig, dockerNetworkConfig, err := r.k8sContainerToDockerConfigs(c, mainContainerID, mainContainerRoot, pod)
	if err != nil {
		return "", fmt.Errorf("error creating the %s container: %s", containerName, err)
	}
	l.WithFields(map[string]interface{}{
		"dockerCfg": logger.ShouldJSON(ctx, *dockerContainerConfig),
		"hostCfg":   logger.ShouldJSON(ctx, *dockerHostConfig),
	}).Infof("Creating other container in docker: %s", c.Name)
	containerCreateBody, err := r.client.ContainerCreate(ctx, dockerContainerConfig, dockerHostConfig, dockerNetworkConfig, containerName)
	if err != nil {
		return "", err
	}
	l.Debugf("Finished creating container %s, CID: %s, Env: %+v", c.Name, containerCreateBody.ID, dockerContainerConfig.Env)
	return containerCreateBody.ID, nil
}

func (r *DockerRuntime) k8sContainerToDockerConfigs(c *runtimeTypes.ExtraContainer, mainContainerID string, mainContainerRoot string, pod *v1.Pod) (*container.Config, *container.HostConfig, *network.NetworkingConfig, error) {
	v1Container := c.V1Container
	// These labels are needed for titus-node-problem-detector and titus-isolate
	// to know that this container is actually part of the "main" one.
	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      mainContainerID,
	}
	mounts := []mount.Mount{
		{
			Type:     "bind",
			Source:   r.dockerCfg.tiniPath,
			ReadOnly: true,
			Target:   "/sbin/docker-init",
		},
		{
			Type:     "bind",
			Source:   path.Join(r.cfg.RuntimeDir, "pod.json"),
			ReadOnly: true,
			Target:   "/titus/run/pod.json",
		},
	}
	if mainContainerRoot != "" {
		mounts = append(
			mounts, mount.Mount{
				Type:     "bind",
				Source:   path.Join(mainContainerRoot, "/logs"),
				Target:   "/logs",
				ReadOnly: false,
			},
			mount.Mount{
				Type:     "bind",
				Source:   path.Join(mainContainerRoot, "/run-shared"),
				Target:   "/run-shared",
				ReadOnly: false,
			},
		)
		volumeMounts, err := r.getContainerSharedVolumeSourceMounts(mainContainerRoot, v1Container, pod)
		if err != nil {
			return nil, nil, nil, err
		}
		mounts = append(mounts, volumeMounts...)
	}
	if r.cfg.MetatronEnabled {
		podMetaronHostPath, _ := r.getPodMetatronFsHostPath()
		// These are the sensitive secrets that live on the tmpfs created prior
		if podMetaronHostPath != "" {
			mounts = append(mounts,
				mount.Mount{
					Type:   "bind",
					Source: podMetaronHostPath,
					Target: "/run/metatron",
					// Allow sidecars to write to metatron folder so it can change cert files if necessary
					ReadOnly: false,
				})
			// These are static certs that the metatron service will create, but we also share them
			// between all containers in the pod.
			if mainContainerRoot != "" {
				mounts = append(mounts, mount.Mount{
					Type:     "bind",
					Source:   path.Join(mainContainerRoot, "/metatron"),
					Target:   "/metatron",
					ReadOnly: false,
				})
			}
		}
	}

	baseEnv := r.c.SortedEnvArray()
	baseEnv = append(baseEnv, "TITUS_CONTAINER_NAME="+v1Container.Name)

	// Only redirect stdout/err if we have shared logs
	if mainContainerRoot != "" {
		baseEnv = append(baseEnv, []string{
			"TITUS_REDIRECT_STDERR=/logs/stderr-" + v1Container.Name,
			"TITUS_REDIRECT_STDOUT=/logs/stdout-" + v1Container.Name,
		}...)
	}
	b := true
	healthcheck := v1ContainerHealthcheckToDockerHealthcheck(v1Container.LivenessProbe)
	dockerContainerConfig := &container.Config{
		// Hostname must be empty here because setting the hostname is incompatible with
		// a container:foo network mode
		Hostname:    "",
		Cmd:         v1Container.Args,
		Image:       v1Container.Image,
		WorkingDir:  v1Container.WorkingDir,
		Entrypoint:  computeExtraContainersDockerEntrypoint(c),
		Labels:      labels,
		Env:         append(baseEnv, v1ConatinerEnvToList(v1Container.Env)...),
		Healthcheck: healthcheck,
	}
	dockerHostConfig := &container.HostConfig{
		NetworkMode: container.NetworkMode("container:" + mainContainerID),
		// Currently there is no restart policy, if the sidecar dies it just dies.
		// TODO: come up with a sane policy here
		RestartPolicy: container.RestartPolicy{
			Name:              "",
			MaximumRetryCount: 0,
		},
		// Currently we don't garbage collect other user containers like the main one
		// TODO: clean these up via the normal garbage collection mechanism instead of this `--rm`
		AutoRemove: true,
		IpcMode:    container.IpcMode("container:" + mainContainerID),
		// Currently only supporting a shared pid namespace with the container, which
		// ensures the other user containers die automatically whe the main one dies.
		PidMode:     container.PidMode("container:" + mainContainerID),
		Privileged:  false,
		VolumesFrom: r.volumeContainers,
		Mounts:      mounts,
		Init:        &b,
		Tmpfs: map[string]string{
			"/run": "rw,exec,size=" + defaultRunTmpFsSize,
		},
	}

	// Security options are inherited from the main container's configuration
	err := setupAdditionalCapabilities(r.c, dockerHostConfig)
	if err != nil {
		return nil, nil, nil, err
	}

	// Nothing extra is needed here, because networking is defined in the HostConfig referencing the main container
	dockerNetworkConfig := &network.NetworkingConfig{}
	return dockerContainerConfig, dockerHostConfig, dockerNetworkConfig, nil
}

// computeExtraContainersDockerEntrypoint takes an extra container, and tries our best to take multiple
// inputs, and computing the most sane entrypoint we can come up with given our requirements. That is:
// 1. We have input k8s container "Command" (docker entrypoint)
// 2. We have the original docker entrypoint on the image
// 3. We have tini, which we need to inject ourselves because we want tini goodness (stdout/err, seccomp, etc)
//
// Given those 3 things, we must return *something* that docker can actually run.
func computeExtraContainersDockerEntrypoint(c *runtimeTypes.ExtraContainer) []string {
	// What docker calls "entrypoint", k8s calls "command", but in addition, we prepend tini
	// The reason we do this is because, even with init=true, docker will only inject tini
	// on containers running in a private pid namespace.
	// On titus, we want tini on *every* container, because it gives us features like stdout/err
	originalEntrypoint := getExtraContainerEntrypoint(c)
	return append([]string{"/sbin/docker-init", "-s", "--"}, originalEntrypoint...)
}

// getExtraContainerEntrypoint computes the original entrypoint that the user
// wants to run, given two sources:
// 1. the input k8s pod "command" (takes precedence)
// 2. the input ENTRYPOINT on the image (should be used if no command is specified on the container spec)
func getExtraContainerEntrypoint(c *runtimeTypes.ExtraContainer) []string {
	if len(c.V1Container.Command) > 0 {
		return c.V1Container.Command
	}
	// Otherwise we provide whatever the original image had, even if it is an empty array
	return c.ImageInspect.ContainerConfig.Entrypoint
}

func v1ConatinerEnvToList(v1Env []v1.EnvVar) []string {
	envList := []string{}
	for _, e := range v1Env {
		envList = append(envList, e.Name+"="+e.Value)
	}
	return envList
}

func v1ContainerHealthcheckToDockerHealthcheck(probe *v1.Probe) *container.HealthConfig {
	if probe == nil {
		return nil
	}
	// TODO: Validate that this healthcheck probe is the only probe the user has requested,
	// and hasn't requested other types of probes we don't support, but earlier, like at the webhook
	// or API
	hc := container.HealthConfig{
		// We use CMD here for the same reasoning behind this:
		// https://github.com/moby/moby/pull/28679
		// We can't assume users have a shell. If the users really need a shell
		// Then they can do their own /bin/sh -c.
		Test:        append([]string{"CMD"}, probe.Exec.Command...),
		Interval:    time.Duration(probe.PeriodSeconds) * time.Second,
		Timeout:     time.Duration(probe.TimeoutSeconds) * time.Second,
		StartPeriod: time.Duration(probe.InitialDelaySeconds) * time.Second,
		Retries:     int(probe.FailureThreshold),
	}
	return &hc
}

// v1MountPropToDockerProp converts the incoming pod mount propagation configuration
// into something that docker can understand, using the documentation for what each means:
// https://kubernetes.io/docs/concepts/storage/volumes/#mount-propagation
func v1MountPropToDockerProp(vm v1.VolumeMount) mount.Propagation {
	// Currently only supporting RShared and RSlave because we are mostly mounting
	// paths in the docker daemon root.
	// Otherwise we get "invalid mount config: must use either propagation mode "rslave" or "rshared" when mount source is within the daemon root"
	// This will need to change if we ever try to support different mount propagations elsewhere.
	if vm.MountPropagation == nil {
		return ""
	}
	mp := *vm.MountPropagation
	switch mp {
	case v1.MountPropagationBidirectional:
		return mount.PropagationRShared
	case v1.MountPropagationHostToContainer:
		return mount.PropagationRSlave
	case v1.MountPropagationNone:
		return ""
	default:
		return ""
	}
}

func (r *DockerRuntime) getUserContainerNames() []string {
	userContainerNames := []string{}
	for _, c := range r.c.ExtraUserContainers() {
		userContainerNames = append(userContainerNames, c.Name)
	}
	return userContainerNames
}

func (r *DockerRuntime) getPlaformContainerNames() []string {
	platformContainerNames := []string{}
	for _, c := range r.c.ExtraPlatformContainers() {
		platformContainerNames = append(platformContainerNames, c.Name)
	}
	return platformContainerNames
}

// getContainerSharedVolumeSourceMounts returns a docker mount object
// for every "SharedContainerVolumeSource", which is a special volume/VolumeMount
// combo in a k8s pod spec that indicates that we should bind-mount one
// directory in one container into another
func (r *DockerRuntime) getContainerSharedVolumeSourceMounts(mainContainerRoot string, c v1.Container, pod *v1.Pod) ([]mount.Mount, error) {
	mounts := []mount.Mount{}
	volumes := pod.Spec.Volumes
	for _, volumeMount := range c.VolumeMounts {
		v := getVolumeByName(volumes, volumeMount.Name)
		if v.Name == "" {
			return nil, fmt.Errorf("couldn't find the corresponding volume for volumeMount %+v", volumeMount)
		}
		if v.FlexVolume != nil && v.FlexVolume.Driver == "SharedContainerVolumeSource" && v.FlexVolume.Options != nil {
			if v.FlexVolume.Options["sourceContainer"] != "main" && v.FlexVolume.Options["sourceContainer"] != "" {
				return nil, fmt.Errorf("only 'main' SharedContainerVolume volumes are supported. Volume: %+v", v)
			}
			m := mount.Mount{
				Type:        "bind",
				Source:      filepath.Join(mainContainerRoot, v.FlexVolume.Options["sourcePath"]),
				Target:      volumeMount.MountPath,
				ReadOnly:    volumeMount.ReadOnly,
				BindOptions: &mount.BindOptions{Propagation: v1MountPropToDockerProp(volumeMount)},
			}
			mounts = append(mounts, m)
		}
	}
	return mounts, nil
}

func getVolumeByName(volumes []v1.Volume, name string) v1.Volume {
	for _, v := range volumes {
		if v.Name == name {
			return v
		}
	}
	return v1.Volume{}
}

// handleDockerEvent takes in docker event messages and may put Task Status updates
// onto the update channel if they are noteworthy.
// This function returns true if the handling of docker events
// should stop.
func (r *DockerRuntime) handleDockerEvent(message events.Message, statusMessageChan chan runtimeTypes.StatusMessage) bool {
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
	cName, err := r.getContainerNameFromDockerEvent(message)
	if err == nil {
		l.Infof("Processing docker event on %s container: %s", cName, action)
	} else {
		l.WithError(err).WithField("message", message).Error("Error looking up the container name for the message, ignoring docker event")
		return nonTerminalDockerEvent
	}
	switch action {
	case "start":
		// Updating the pod is relativly expensive, so we only send the update and consider the pod "running"
		// if the the docker event came from the main container
		if cName == mainContainerName {
			statusMessageChan <- runtimeTypes.StatusMessage{
				Status: runtimeTypes.StatusRunning,
				Msg:    cName + " container is now running",
			}
			return nonTerminalDockerEvent
		}
		l.Debugf("Skipping docker start event for %s, no need to update the pod", cName)
		return nonTerminalDockerEvent
	case "die":
		exitCode := message.Actor.Attributes["exitCode"]
		if exitCode == "0" {
			statusMessageChan <- runtimeTypes.StatusMessage{
				Status: runtimeTypes.StatusFinished,
				Msg:    cName + " container successfully exited with 0",
			}
			return isTerminalDockerEvent
		} else if exitCode == "137" && cName != mainContainerName {
			// An exit code of 137 means it was killed.
			// If we are not on the 'main' container, and docker doesn't have us in the 'oom' case,
			// then it *probably* means that a sidecar container got killed while we were tearing down the pod
			// In this case, we should not update the task status, and let the "real" docker event do that for us.
			l.Infof("Ignoring %s container dying with exit code 137, probably meaning that it was killed while the main container was exiting", cName)
			return nonTerminalDockerEvent
		} else {
			statusMessageChan <- runtimeTypes.StatusMessage{
				Status: runtimeTypes.StatusFailed,
				Msg:    fmt.Sprintf("%s container exited with code %s", cName, exitCode),
			}
			return isTerminalDockerEvent
		}
	case "health_status":
		// TODO: Update the actual health state of the container
		// so that ContainerStatus reflects what docker knows
		statusMessageChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusRunning,
			Msg:    fmt.Sprintf("%s Docker health status: %s", cName, message.Status),
		}
		return nonTerminalDockerEvent
	case "kill":
		// TODO: Handle the difference between platform/user sidecar, not all
		// "kills"s should result in a Failed
		if cName == mainContainerName {
			statusMessageChan <- runtimeTypes.StatusMessage{
				Status: runtimeTypes.StatusFailed,
				Msg:    fmt.Sprintf("%s container killed with signal %s", cName, message.Actor.Attributes["signal"]),
			}
			return isTerminalDockerEvent
		}
		l.Debugf("Skipping docker kill event for %s, no need to update the pod", cName)
		return nonTerminalDockerEvent
	case "oom":
		// TODO: Handle the difference between platform/user sidecar, not all
		// "oom"s should result in a Failed
		statusMessageChan <- runtimeTypes.StatusMessage{
			Status: runtimeTypes.StatusFailed,
			Msg:    fmt.Sprintf("%s container %s exited due to OOMKilled", cName, r.c.TaskID()),
		}
		return isTerminalDockerEvent
	// Ignore exec events entirely
	case "exec_create", "exec_start", "exec_die":
		return nonTerminalDockerEvent
	default:
		log.WithField("taskID", r.c.ID()).Info("Received unexpected docker event: ", message)
		return nonTerminalDockerEvent
	}
}

// getContainerNameFromDockerEvent pulls out the titus-friendly container name (whatever the user specified)
// out of a docker event. Docker events look like this:
//
// {"status":"exec_die","id":"408563a253eb82bf0e76e3cd32594dc55a968a16dc494c45d8d46c7da465ce82",
//  "from":"busybox","Type":"container","Action":"exec_die",
//  "Actor":{
//    "ID":"408563a253eb82bf0e76e3cd32594dc55a968a16dc494c45d8d46c7da465ce82",
//    "Attributes":{
//      "execID":"3514a0192401ad20c1bbf693d38d64e036b8ca2b700894cb1cea9df43dcfa34f","exitCode":"1","image":"busybox","name":"123-foobar"}
//     },
//   "scope":"local","time":1626119653,"timeNano":1626119653617364285
// }
//
// For Titus, the id (container id) is the best way to correlate where this
// event is coming from.
func (r *DockerRuntime) getContainerNameFromDockerEvent(m events.Message) (string, error) {
	return r.getContainerNameFromID(m.ID)
}

func (r *DockerRuntime) getContainerNameFromID(id string) (string, error) {
	// Most common case, just the main container, we return the string "main"
	if id == r.c.ID() {
		return mainContainerName, nil
	}
	for _, c := range r.c.ExtraPlatformContainers() {
		if id == c.Status.ContainerID {
			return c.Name, nil
		}
	}
	for _, c := range r.c.ExtraUserContainers() {
		if id == c.Status.ContainerID {
			return c.Name, nil
		}
	}
	return "", fmt.Errorf("Unknown container couldn't find the container name for cid " + id)
}

func (r *DockerRuntime) setupEFSMounts(parentCtx context.Context, c runtimeTypes.Container, rootFile *os.File, cred *ucred) error {
	baseMountOptions := []string{"vers=4.1,rsize=1048576,wsize=1048576,timeo=600,retrans=2"}
	for _, nfs := range c.NFSMounts() {
		// Todo: Make into a const
		// Although 5 minutes is probably far too much here, this window is okay to be large
		// because the parent window should be greater
		ctx, cancel := context.WithTimeout(parentCtx, mountTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/apps/titus-executor/bin/titus-mount-nfs", strconv.Itoa(int(cred.pid))) // nolint: gosec
		flags := 0
		if nfs.ReadOnly {
			flags = flags | MS_RDONLY
		}
		mountOptions := append(
			baseMountOptions,
			fmt.Sprintf("fsc=%s", c.TaskID()),
			fmt.Sprintf("source=[%s]:%s", nfs.Server, nfs.ServerPath),
		)
		cmd.Env = []string{
			fmt.Sprintf("MOUNT_TARGET=%s", nfs.MountPoint),
			fmt.Sprintf("MOUNT_NFS_HOSTNAME=%s", nfs.Server),
			fmt.Sprintf("MOUNT_FLAGS=%d", flags),
			fmt.Sprintf("MOUNT_OPTIONS=%s", strings.Join(mountOptions, ",")),
		}

		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Mount failure: %+v: %s", nfs, string(stdoutStderr))
		}
		cancel()

	}

	return nil
}

// Setup listener
func (r *DockerRuntime) setupPreStartTini(ctx context.Context, c runtimeTypes.Container) (*net.UnixListener, error) {
	if runtime.GOOS == "darwin" { //nolint:goconst
		// On darwin (docker-for-mac), it is not possible to share
		// darwin unix sockets with a linux guest container: https://github.com/docker/for-mac/issues/483
		// Instead we gracefully degrade with a nil listener and move on
		return nil, nil
	}

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
	if l == nil {
		// In situations where we don't have a listener to use (docker-for-mac)
		// we can gracefully degrade and not do additional log or system service setup
		return "", nil, nil, nil, nil
	}

	genericConn, err := l.Accept()
	if err != nil {
		if ctx.Err() != nil {
			log.WithField("ctxError", ctx.Err()).Error("Never received connection from container from tini: ", err)
			return "", nil, nil, nil, errors.New("Never received connection from container from tini")
		}
		log.WithError(err).Error("Error accepting tini connection from container")
		return "", nil, nil, nil, fmt.Errorf("error accepting tini connection from container: %w", err)
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
		return "", nil, nil, fmt.Errorf("Error getting peerinfo: %w", err)

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
		return fmt.Errorf("error mounting proc pid1 in titus init: %w", err)
	}

	if r.cfg.UseNewNetworkDriver && c.VPCAllocation() != nil {
		// This writes to C, and registers runtime cleanup functions, this is a write
		// and it writes to a bunch of pointers

		// afaik, since this is the only one *modifying* data in the container object, we should be okay
		group.Go(func() error {
			cf, err := setupNetworking(errGroupCtx, r.dockerCfg.burst, c, cred)
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
			err := setupScheduler(cred)
			if err != nil {
				log.WithError(err).Warning("Non-fatal error when bumping the priority of tini: %w", err)
			}
			return nil
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

	r.registerRuntimeCleanup(func() error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := stopSystemServices(ctx, c); err != nil {
			log.WithError(err).Error("Unable to stop system services")
			return fmt.Errorf("Unable to stop system services: %w", err)
		}
		return nil
	})

	return nil
}

func setupNetworking(ctx context.Context, burst bool, c runtimeTypes.Container, cred ucred) (cleanupFunc, error) { // nolint: gocyclo
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	log.Info("Setting up container network")
	var result vpcTypes.WiringStatus

	netnsPath := filepath.Join("/proc/", strconv.Itoa(int(cred.pid)), "ns", "net")
	netnsFile, err := os.Open(netnsPath)
	if err != nil {
		return nil, err
	}
	defer shouldClose(netnsFile)

	setupCommand := exec.CommandContext(ctx, vpcToolPath(), "setup-container", "--netns", "3") // nolint: gosec
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

	allocation := c.VPCAllocation()
	marshaler := protojson.MarshalOptions{
		Indent: "\t",
	}
	data, err := marshaler.Marshal(allocation)
	if err != nil {
		return nil, err
	}

	_, err = stdin.Write(data)
	if err != nil {
		return nil, fmt.Errorf("Could not write data to stdin pipe of setup container: %w", err)
	}

	if err := json.NewDecoder(stdout).Decode(&result); err != nil {
		return nil, fmt.Errorf("Unable to read json from pipe during setup-container: %+v", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("Network setup error: %s", result.Error)
	}

	f2, err := os.Open(netnsPath)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to open container network namespace file")
	}
	return func() error {
		return teardownCommand(f2, allocation)
	}, nil

}

func teardownCommand(netnsFile *os.File, allocation *vpcapi.Assignment) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	defer shouldClose(netnsFile)

	teardownCommand := exec.CommandContext(ctx, vpcToolPath(), "teardown-container", "--netns", "3") // nolint: gosec
	stdin, err := teardownCommand.StdinPipe()
	if err != nil {
		return errors.Wrap(err, "Cannot get teardown stdin")
	}

	teardownCommand.Stdout = os.Stdout
	teardownCommand.Stderr = os.Stderr
	teardownCommand.ExtraFiles = []*os.File{netnsFile}
	err = teardownCommand.Start()
	if err != nil {
		log.WithError(err).Error("Experienced error tearing down container")
		return errors.Wrap(err, "Could not start teardown command")
	}

	marshaler := protojson.MarshalOptions{
		Indent: "\t",
	}
	data, err := marshaler.Marshal(allocation)
	if err != nil {
		return errors.Wrap(err, "Unable to encode allocation for teardown command")
	}

	_, err = stdin.Write(data)
	if err != nil {
		return fmt.Errorf("Unable to write allocation to stdin of teardown command: %w", err)
	}

	err = teardownCommand.Wait()
	if err != nil {
		return errors.Wrap(err, "Unable to run teardown command")
	}
	return nil
}

func tellTiniToLaunch(conn *net.UnixConn) error {
	if conn == nil {
		return nil
	}
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
func (r *DockerRuntime) Kill(ctx context.Context, wasKilled bool) error { // nolint: gocyclo
	ctx, span := trace.StartSpan(ctx, "Kill")
	defer span.End()

	var errs *multierror.Error
	containerStopTimeout := defaultKillWait

	if killWait := r.c.KillWaitSeconds(); killWait != nil && *killWait != 0 {
		containerStopTimeout = time.Second * time.Duration(*killWait)
	}
	cStopPtr := &containerStopTimeout

	if wasKilled {
		// We're being told by the API to stop, so use the configured stop timeout
		logger.G(ctx).WithField("stopTimeout", containerStopTimeout.Seconds()).Info("Shutting down containers because we were asked to stop from the API")
	} else {
		// The container either finished or died, so the user's workload isn't running. There's no point in delaying the stop.
		cStopPtr = nil
		logger.G(ctx).Info("Stopping+Cleaning up containers because they finished or died")
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

	if err := r.runAllPreStopHooks(ctx); err.ErrorOrNil() != nil {
		log.Error("Error encountered when running preStop hooks, continuing to shutdown regardless", err)
	}

	logger.G(ctx).Debug("Stopping main container")
	if err := r.client.ContainerStop(context.TODO(), r.c.ID(), cStopPtr); err != nil {
		r.metrics.Counter("titus.executor.dockerStopContainerError", 1, nil)
		log.Errorf("container %s : stop %v", r.c.TaskID(), err)
		errs = multierror.Append(errs, err)
	} else {
		goto stopped
	}

	logger.G(ctx).Debug("Killing main container")
	if err := r.client.ContainerKill(context.TODO(), r.c.ID(), "SIGKILL"); err != nil {
		r.metrics.Counter("titus.executor.dockerKillContainerError", 1, nil)
		log.Errorf("container %s : kill %v", r.c.TaskID(), err)
		errs = multierror.Append(errs, err)
	}

	// NOTE: We don't stop or kill the sidecar containers here, because they have `autoremove: true`,
	// and die naturally when the main container dies due to a shared pid namespace.

stopped:

	logger.G(ctx).Debug("Main container stop completed")
	if gpuInfo := r.c.GPUInfo(); gpuInfo != nil {
		numDealloc := gpuInfo.Deallocate()
		logger.G(ctx).WithField("numDealloc", numDealloc).Info("Deallocated GPU devices for task")
	}

	err := errs.ErrorOrNil()
	tracehelpers.SetStatus(err, span)
	return err
}

// runAllPreStopHooks emulates k8s lifecycle preStop hook sequence
// https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#container-hooks
// Hooks are blocking, and pods should not assume any particular order
func (r *DockerRuntime) runAllPreStopHooks(ctx context.Context) *multierror.Error {
	var errs *multierror.Error
	for _, c := range r.c.ExtraPlatformContainers() {
		err := r.runPreStopHookIfDefined(ctx, &c.V1Container, c.Status.ContainerID)
		errs = multierror.Append(errs, err)
	}
	for _, c := range r.c.ExtraUserContainers() {
		err := r.runPreStopHookIfDefined(ctx, &c.V1Container, c.Status.ContainerID)
		errs = multierror.Append(errs, err)

	}
	err := r.runPreStopHookIfDefined(ctx, &r.c.Pod().Spec.Containers[0], r.c.ID())
	errs = multierror.Append(errs, err)
	return errs
}

func (r *DockerRuntime) runPreStopHookIfDefined(ctx context.Context, c *v1.Container, cid string) error {
	if c.Lifecycle == nil {
		return nil
	}
	if c.Lifecycle.PreStop == nil {
		return nil
	}
	if cid == "" {
		return fmt.Errorf("Unable to run any preStop hooks for %s container, cid is empty?", c.Name)
	}
	if c.Lifecycle.PreStop.HTTPGet != nil {
		return fmt.Errorf("HTTP prestop hook on %s container not supported, ignoring", c.Name)
	}
	if c.Lifecycle.PreStop.TCPSocket != nil {
		return fmt.Errorf("TCPSocket prestop hook on %s container not supported, ignoring", c.Name)
	}
	if c.Lifecycle.PreStop.Exec == nil {
		return nil
	}
	if c.Lifecycle.PreStop.Exec.Command == nil {
		return nil
	}
	return r.runBlockingPreStopExec(ctx, c.Lifecycle.PreStop.Exec.Command, cid, c.Name)
}

// runBlockingPreStopExec runs 'docker exec' in a container, for the purposes of running a preStop hook for a container
// This is meant as a best effort sort of thing, where errors are reported, but callers of this function should just report
// on them. Tini is also involved, because it difficult to debug these preStop hooks, so having the output automatically
// redirected to a file in /logs allows users to see them after the fact.
func (r *DockerRuntime) runBlockingPreStopExec(ctx context.Context, command []string, cid string, cName string) error {
	logger.G(ctx).Debugf("About to run blocking prestop exec (%v) on container %s", command, cName)
	// Tini is added here
	env := []string{
		"TITUS_REDIRECT_STDERR=/logs/prestop." + cName + ".err",
		"TITUS_REDIRECT_STDOUT=/logs/prestop." + cName + ".out",
	}
	tiniCommand := []string{"/sbin/docker-init", "-s", "--"}
	optionsCreate := dockerTypes.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          append(tiniCommand, command...),
		Env:          env,
	}
	createResponse, err := r.client.ContainerExecCreate(ctx, cid, optionsCreate)
	if err != nil {
		return fmt.Errorf("Error when creating exec (%v) for %s: %w", command, cName, err)
	}
	optionsStart := dockerTypes.ExecStartCheck{
		Detach: false,
		Tty:    false,
	}
	err = r.client.ContainerExecStart(ctx, createResponse.ID, optionsStart)
	if err != nil {
		return fmt.Errorf("Error when starting exec (%v) for %s: %w", command, cName, err)
	}
	inspectResponse, err := r.client.ContainerExecInspect(ctx, createResponse.ID)
	if err != nil {
		return fmt.Errorf("Error when inspecting exec attach (%v) for %s: %w", command, cName, ctx.Err())
	}
	logger.G(ctx).Infof("Exec on (cid %s) exited with %d", cid, inspectResponse.ExitCode)
	return nil
}

// Cleanup runs the registered callbacks for a container
func (r *DockerRuntime) Cleanup(parentCtx context.Context) error {
	_, span := trace.StartSpan(parentCtx, "Cleanup")
	defer span.End()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = trace.NewContext(ctx, span)

	var errs *multierror.Error

	cro := types.ContainerRemoveOptions{
		RemoveVolumes: true,
		RemoveLinks:   false,
		Force:         true,
	}

	if err := r.client.ContainerRemove(ctx, r.c.ID(), cro); err != nil {
		r.metrics.Counter("titus.executor.dockerRemoveContainerError", 1, nil)
		log.Errorf("Failed to remove container '%s' with ID: %s: %v", r.c.TaskID(), r.c.ID(), err)
		errs = multierror.Append(errs, err)
	}

	r.cleanupFuncLock.Lock()
	defer r.cleanupFuncLock.Unlock()
	for i := len(r.cleanup) - 1; i >= 0; i-- {
		errs = multierror.Append(errs, r.cleanup[i]())
	}

	err := errs.ErrorOrNil()
	tracehelpers.SetStatus(err, span)
	return err
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
