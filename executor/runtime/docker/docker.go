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
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/Netflix/titus-executor/nvidia"
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
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	"gopkg.in/urfave/cli.v1"
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
	// See: TITUS-1231, this is added as extra padding for container initialization
	builtInDiskBuffer       = 1100 // In megabytes, includes extra space for /logs.
	defaultNetworkBandwidth = 128 * MB
	defaultKillWait         = 10 * time.Second
	defaultRunTmpFsSize     = "134217728" // 128 MiB
	defaultRunLockTmpFsSize = "5242880"   // 5 MiB: the default setting on Ubuntu Xenial
	trueString              = "true"
	jumboFrameParam         = "titusParameter.agent.allowNetworkJumbo"
	systemdImageLabel       = "com.netflix.titus.systemd"
)

// Config represents the configuration for the Docker titus runtime
type Config struct { // nolint: maligned
	cfsBandwidthPeriod              uint64
	tiniVerbosity                   int
	batchSize                       int
	burst                           bool
	securityConvergenceTimeout      time.Duration
	pidLimit                        int
	prepareTimeout                  time.Duration
	startTimeout                    time.Duration
	bumpTiniSchedPriority           bool
	waitForSecurityGroupLockTimeout time.Duration
	ipRefreshTimeout                time.Duration

	titusIsolateBlockTime   time.Duration
	enableTitusIsolateBlock bool
}

// NewConfig generates a configuration, with a set of flags tied to it for the docker runtime
func NewConfig() (*Config, []cli.Flag) {
	cfg := &Config{}
	flags := []cli.Flag{
		cli.Uint64Flag{
			Name:        "titus.executor.cfsBandwidthPeriod",
			Value:       100000,
			Destination: &cfg.cfsBandwidthPeriod,
		},
		cli.IntFlag{
			Name:        "titus.executor.tiniVerbosity",
			Value:       0,
			Destination: &cfg.tiniVerbosity,
		},
		cli.IntFlag{
			Name:        "titus.executor.networking.batchSize",
			Value:       4,
			Destination: &cfg.batchSize,
		},
		cli.BoolFlag{
			Name:        "titus.executor.networking.burst",
			Destination: &cfg.burst,
		},
		cli.DurationFlag{
			Name:        "titus.executor.networking.securityConvergenceTimeout",
			Destination: &cfg.securityConvergenceTimeout,
			Value:       time.Second * 10,
		},
		cli.IntFlag{
			Name:        "titus.executor.pidLimit",
			Value:       100000,
			Destination: &cfg.pidLimit,
		},
		cli.DurationFlag{
			Name:        "titus.executor.timeouts.prepare",
			Value:       time.Minute * 10,
			Destination: &cfg.prepareTimeout,
		},
		cli.DurationFlag{
			Name:        "titus.executor.timeouts.start",
			Value:       time.Minute * 10,
			Destination: &cfg.startTimeout,
		},
		cli.DurationFlag{
			Name:        "titus.executor.waitForSecurityGroupLockTimeout",
			Value:       time.Minute * 1,
			Destination: &cfg.waitForSecurityGroupLockTimeout,
		},
		cli.DurationFlag{
			Name:        "titus.executor.networking.ipRefreshTimeout",
			Destination: &cfg.ipRefreshTimeout,
			Value:       time.Second * 10,
		},
		cli.DurationFlag{
			Name:   "titus.executor.titusIsolateBlockTime",
			EnvVar: "TITUS_EXECUTOR_TITUS_ISOLATE_BLOCK_TIME",
			// The default value inside of the Titus Isolate code is 10 seconds.
			// we can wait longer than it
			Value:       30 * time.Second,
			Destination: &cfg.titusIsolateBlockTime,
		},
		cli.BoolFlag{
			Name:        "titus.executor.enableTitusIsolateBlock",
			EnvVar:      "ENABLE_TITUS_ISOLATE_BLOCK",
			Destination: &cfg.enableTitusIsolateBlock,
		},
		// Allow the usage of a realtime scheduling policy to be optional on systems that don't have it properly configured
		// by default, i.e.: docker-for-mac.
		cli.BoolTFlag{
			Name:        "titus.executor.tiniSchedPriority",
			Destination: &cfg.bumpTiniSchedPriority,
			Usage: "enable a realtime scheduling priority for tini (PID=1), so it can always reap processes on contended " +
				"systems. Kernels with CONFIG_RT_GROUP_SCHED=y require all cgroups in the hierarchy to have some " +
				"cpu.rt_runtime_us allocated to each one of them",
		},
	}
	return cfg, flags
}

// GenerateConfiguration is only meant to validate the behaviour of parsing command line arguments
func GenerateConfiguration(args []string) (*Config, error) {
	cfg, flags := NewConfig()

	app := cli.NewApp()
	app.Flags = flags
	app.Action = func(c *cli.Context) error {
		return nil
	}
	if args == nil {
		args = []string{}
	}

	args = append([]string{"fakename"}, args...)

	return cfg, app.Run(args)
}

func shouldStartMetatronSync(cfg *config.Config, c *runtimeTypes.Container) bool {
	if cfg.MetatronEnabled && c.TitusInfo.GetMetatronCreds() != nil {
		return true
	}

	return false
}

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
}

// NewDockerRuntime provides a Runtime implementation on Docker
func NewDockerRuntime(executorCtx context.Context, m metrics.Reporter, dockerCfg Config, cfg config.Config) (runtimeTypes.Runtime, error) {
	log.Info("New Docker client, to host ", cfg.DockerHost)
	client, err := docker.NewClient(cfg.DockerHost, "1.26", nil, map[string]string{})

	if err != nil {
		return nil, err
	}

	info, err := client.Info(executorCtx)

	if err != nil {
		return nil, err
	}

	dockerRuntime := &DockerRuntime{
		metrics:         m,
		registryAuthCfg: nil, // we don't need registry authentication yet
		client:          client,
		cfg:             cfg,
		dockerCfg:       dockerCfg,
	}

	dockerRuntime.pidCgroupPath, err = getOwnCgroup("pids")
	if err != nil {
		return nil, err
	}

	// TODO: Check
	dockerRuntime.awsRegion = os.Getenv("EC2_REGION")
	err = setupLoggingInfra(dockerRuntime)
	if err != nil {
		return nil, err
	}

	go func() {
		<-executorCtx.Done()
		err = os.RemoveAll(dockerRuntime.tiniSocketDir)
		if err != nil {
			log.Errorf("Could not cleanup tini socket directory %s because: %v", dockerRuntime.tiniSocketDir, err)
		}
	}()

	dockerRuntime.storageOptEnabled = shouldEnableStorageOpts(info)

	if strings.Contains(info.InitBinary, "tini") {
		dockerRuntime.tiniEnabled = true
	} else {
		log.WithField("initBinary", info.InitBinary).Warning("Docker runtime disabling Tini support")
	}

	return dockerRuntime, nil
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

func (r *DockerRuntime) validateEFSMounts(c *runtimeTypes.Container) error {
	if len(c.TitusInfo.GetEfsConfigInfo()) > 0 && !r.tiniEnabled {
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

func maybeSetCFSBandwidth(cfsBandwidthPeriod uint64, c *runtimeTypes.Container, hostCfg *container.HostConfig) {
	cpuBurst := c.TitusInfo.GetAllowCpuBursting()
	logEntry := log.WithField("taskID", c.TaskID).WithField("cpuBurst", cpuBurst)

	if cpuBurst {
		logEntry.Info("Falling back to shares since CPU bursting is enabled")
		setShares(logEntry, c, hostCfg)
		return
	}

	setCFSBandwidth(logEntry, cfsBandwidthPeriod, c, hostCfg)
}

func setCFSBandwidth(logEntry *log.Entry, cfsBandwidthPeriod uint64, c *runtimeTypes.Container, hostCfg *container.HostConfig) {
	quota := int64(cfsBandwidthPeriod) * c.Resources.CPU
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

func setNanoCPUs(logEntry *log.Entry, c *runtimeTypes.Container, hostCfg *container.HostConfig) {
	nanoCPUs := c.Resources.CPU * 1e9
	logEntry.WithField("nanoCPUs", nanoCPUs).Info("Setting Nano CPUs")
	// TODO: Verify that .CPUPeriod, and .CPUQuota are not set
	hostCfg.NanoCPUs = nanoCPUs
}

func setShares(logEntry *log.Entry, c *runtimeTypes.Container, hostCfg *container.HostConfig) {
	shares := c.Resources.CPU * 100
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

func maybeAddOptimisticDad(sysctl map[string]string) {
	if unix.Access("/proc/sys/net/ipv6/conf/default/use_optimistic", 0) == nil {
		sysctl["net.ipv6.conf.default.use_optimistic"] = "1"
	}
	if unix.Access("/proc/sys/net/ipv6/conf/default/optimistic_dad", 0) == nil {
		sysctl["net.ipv6.conf.default.optimistic_dad"] = "1"
	}
}

func (r *DockerRuntime) dockerConfig(c *runtimeTypes.Container, binds []string, imageSize int64, volumeContainers []string) (*container.Config, *container.HostConfig, error) { // nolint: gocyclo
	// Extract the entrypoint from the proto. If the proto is empty, pass
	// an empty entrypoint and let Docker extract it from the image.
	entrypoint, cmd, err := c.Process()
	if err != nil {
		return nil, nil, err
	}

	c.Env["TITUS_IAM_ROLE"], err = c.GetIamProfile()
	if err != nil {
		return nil, nil, err
	}

	if optimisticTokenFetch, parseErr := c.GetOptimisticIAMTokenFetch(); parseErr != nil {
		return nil, nil, parseErr
	} else if optimisticTokenFetch {
		c.Env[metadataserverTypes.TitusOptimisticIAMVariableName] = "true"
	}

	// hostname style: ip-{ip-addr} or {task ID}
	hostname, err := c.ComputeHostname()
	if err != nil {
		return nil, nil, err
	}

	tty, err := c.GetTty()
	if err != nil {
		return nil, nil, err
	}

	containerCfg := &container.Config{
		Image:      c.QualifiedImageName(),
		Entrypoint: entrypoint,
		Cmd:        cmd,
		Labels:     c.Labels,
		Volumes:    map[string]struct{}{},
		Hostname:   hostname,
		Tty:        tty,
	}

	useInit := true
	hostCfg := &container.HostConfig{
		AutoRemove: false,
		Privileged: false,
		Binds:      binds,
		ExtraHosts: []string{fmt.Sprintf("%s:%s", hostname, c.Allocation.IPV4Address)},
		Sysctls: map[string]string{
			"net.ipv4.tcp_ecn":                    "1",
			"net.ipv6.conf.all.disable_ipv6":      "0",
			"net.ipv6.conf.default.disable_ipv6":  "0",
			"net.ipv6.conf.lo.disable_ipv6":       "0",
			"net.ipv6.conf.default.stable_secret": stableSecret(), // This is to ensure each container sets their addresses differently
		},
		Init: &useInit,
	}
	for _, containerName := range volumeContainers {
		log.Infof("Setting up VolumesFrom from container %s", containerName)
		hostCfg.VolumesFrom = append(hostCfg.VolumesFrom, fmt.Sprintf("%s:ro", containerName))
	}
	maybeAddOptimisticDad(hostCfg.Sysctls)
	hostCfg.CgroupParent = r.pidCgroupPath
	c.RegisterRuntimeCleanup(func() error {
		return cleanupCgroups(r.pidCgroupPath)
	})

	hostCfg.PidsLimit = int64(r.dockerCfg.pidLimit)
	hostCfg.Memory = c.Resources.Mem * MiB
	hostCfg.MemorySwap = 0
	// Limit this to a fairly small number to prevent the containers from ever getting more CPU shares than the system
	// 16 is chosen, because our biggest machines have 32 cores, and the default shares for the root cgroup is 1024,
	// And this means that at minimum the containers should be able to use about 50% of the machine.

	// We still need to scale this by CPU count to not break atlas metrics
	hostCfg.CPUShares = 100 * c.Resources.CPU

	// Maybe set cfs bandwidth has to be called _after_
	maybeSetCFSBandwidth(r.dockerCfg.cfsBandwidthPeriod, c, hostCfg)

	// Always setup tmpfs: it's needed to ensure Metatron credentials don't persist across reboots and for SystemD to work
	hostCfg.Tmpfs = map[string]string{
		"/run": "rw,exec,size=" + defaultRunTmpFsSize,
	}

	if c.IsSystemD {
		// systemd requires `/run/lock` to be a separate mount from `/run`
		hostCfg.Tmpfs["/run/lock"] = "rw,exec,size=" + defaultRunLockTmpFsSize
	}

	if r.storageOptEnabled {
		hostCfg.StorageOpt = map[string]string{
			"size": fmt.Sprintf("%dM", c.Resources.Disk+builtInDiskBuffer+uint64(imageSize/MiB)),
		}
	}

	coreLimit := &units.Ulimit{
		Name: "core",
		Soft: int64((c.Resources.Disk * MiB) + 1*GiB),
		Hard: int64((c.Resources.Disk * MiB) + 1*GiB),
	}
	hostCfg.Ulimits = []*units.Ulimit{coreLimit}

	// This is just factored out mutation of these objects to make the code cleaner.
	r.setupLogs(c, containerCfg, hostCfg)

	if r.cfg.PrivilegedContainersEnabled {
		// Note: ATM, this is used to enable MCE to use FUSE within a container and
		// is expected to only be used in their account. So these are the only capabilities
		// we allow.
		log.Infof("Enabling privileged access for task %s", c.TaskID)
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
	containerCfg.Labels["titus.vpc.ipv4"] = c.Allocation.IPV4Address // deprecated
	containerCfg.Labels["titus.net.ipv4"] = c.Allocation.IPV4Address

	// TODO(fabio): find a way to avoid regenerating the env map
	c.Env["EC2_LOCAL_IPV4"] = c.Allocation.IPV4Address
	if c.Allocation.IPV6Address != "" {
		c.Env["EC2_IPV6S"] = c.Allocation.IPV6Address
	}
	c.Env["EC2_VPC_ID"] = c.Allocation.VPC
	c.Env["EC2_INTERFACE_ID"] = c.Allocation.ENI

	if r.cfg.UseNewNetworkDriver {
		hostCfg.NetworkMode = container.NetworkMode("none")
	}

	if batch := c.GetBatch(); batch != nil {
		c.Env["TITUS_BATCH"] = *batch
	}

	// This must got after all setup
	containerCfg.Env = c.GetSortedEnvArray()

	return containerCfg, hostCfg, nil
}

func (r *DockerRuntime) setupLogs(c *runtimeTypes.Container, containerCfg *container.Config, hostCfg *container.HostConfig) {
	// TODO(fabio): move this to a daemon-level config
	hostCfg.LogConfig = container.LogConfig{
		Type: "journald",
	}

	t := true
	hostCfg.Init = &t
	socketFileName := tiniSocketFileName(c)

	hostCfg.Binds = append(hostCfg.Binds, r.tiniSocketDir+":/titus-executor-sockets:ro")
	c.Env["TITUS_REDIRECT_STDERR"] = "/logs/stderr"
	c.Env["TITUS_REDIRECT_STDOUT"] = "/logs/stdout"
	c.Env["TITUS_UNIX_CB_PATH"] = filepath.Join("/titus-executor-sockets/", socketFileName)
	/* Require us to send a message to tini in order to let it know we're ready for it to start the container */
	c.Env["TITUS_CONFIRM"] = trueString
	if r.dockerCfg.tiniVerbosity > 0 {
		c.Env["TINI_VERBOSITY"] = strconv.Itoa(r.dockerCfg.tiniVerbosity)
	}
}

func (r *DockerRuntime) hostOSPathToTiniSocket(c *runtimeTypes.Container) string {
	socketFileName := tiniSocketFileName(c)

	return filepath.Join(r.tiniSocketDir, socketFileName)
}

func tiniSocketFileName(c *runtimeTypes.Container) string {
	return fmt.Sprintf("%s.socket", c.TaskID)
}

func netflixLoggerTempDir(cfg config.Config, c *runtimeTypes.Container) string {
	return filepath.Join(cfg.LogsTmpDir, c.TaskID)
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
		if docker.IsErrImageNotFound(err) {
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
func (r *DockerRuntime) DockerPull(ctx context.Context, c *runtimeTypes.Container) (*types.ImageInspect, error) {
	imgName := c.QualifiedImageName()
	logger := log.WithField("imageName", imgName)

	if c.ImageHasDigest() {
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
func setSystemdRunning(log *log.Entry, imageInfo types.ImageInspect, c *runtimeTypes.Container) error {
	l := log.WithField("imageName", c.QualifiedImageName())

	if systemdBool, ok := imageInfo.Config.Labels[systemdImageLabel]; ok {
		l.WithField("systemdLabel", systemdBool).Info("SystemD image label set")

		val, err := strconv.ParseBool(systemdBool)
		if err != nil {
			l.WithError(err).Error("Error parsing systemd image label")
			return errors.Wrap(err, "error parsing systemd image label")
		}

		c.IsSystemD = val
		return nil
	}

	return nil
}

// This will setup c.Allocation
func prepareNetworkDriver(parentCtx context.Context, cfg Config, c *runtimeTypes.Container) error { // nolint: gocyclo
	log.Printf("Configuring VPC network for %s", c.TaskID)

	args := []string{
		"allocate-network",
		"--device-idx", strconv.Itoa(c.NormalizedENIIndex),
		"--security-groups", strings.Join(c.SecurityGroupIDs, ","),
		"--security-convergence-timeout", cfg.securityConvergenceTimeout.String(),
		"--ip-refresh-timeout", cfg.ipRefreshTimeout.String(),
		"--batch-size", strconv.Itoa(cfg.batchSize),
	}

	assignIPv6Address, err := c.AssignIPv6Address()
	if err != nil {
		return err
	}
	if assignIPv6Address {
		args = append(args, "--allocate-ipv6-address=true")
	}

	// This blocks, and ignores kills.
	if !c.TitusInfo.GetIgnoreLaunchGuard() {
		args = append(args, "--wait-for-sg-lock-timeout", cfg.waitForSecurityGroupLockTimeout.String())
	}

	// This channel indicates when allocation is done, successful or not
	allocateDone := false

	// This ctx should only be cancelled when prepare is interrupted
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-parentCtx.Done()
		if !allocateDone {
			log.Error("Terminating allocate-network prematurely due to context cancellation")
			cancel()
		}
	}()
	// We intentionally don't use context here, because context only KILLs.
	// Instead we rely on the idea of the cleanup function below.

	c.AllocationCommand = exec.CommandContext(ctx, vpcToolPath(), args...) // nolint: gosec
	c.AllocationCommandStatus = make(chan error)

	c.AllocationCommand.Stderr = os.Stderr
	stdoutPipe, err := c.AllocationCommand.StdoutPipe()
	if err != nil {
		return err
	}

	err = c.AllocationCommand.Start()
	if err != nil {
		return err
	}

	err = json.NewDecoder(stdoutPipe).Decode(&c.Allocation)
	if err != nil {
		// This should kill the process
		cancel()
		log.Error("Unable to read JSON from allocate command: ", err)
		return fmt.Errorf("Unable to read json from pipe: %+v", err) // nolint: gosec
	}

	c.RegisterRuntimeCleanup(func() error {
		_ = c.AllocationCommand.Process.Signal(unix.SIGTERM) // nolint: gosec
		time.AfterFunc(5*time.Minute, cancel)
		defer cancel()
		select {
		case e, ok := <-c.AllocationCommandStatus:
			if !ok {
				return nil
			}
			return e
		case <-ctx.Done():
			return fmt.Errorf("allocate command: %s", ctx.Err().Error())
		}
	})

	go func() {
		defer close(c.AllocationCommandStatus)
		e := c.AllocationCommand.Wait()
		if e == nil {
			log.Info("Allocate command exited with no error")
			return
		}
		e = ctx.Err()
		if e != nil {
			log.WithError(e).Info("Allocate command canceled")
			return
		}

		log.Error("Allocate command exited with error: ", err)

		if exitErr, ok := e.(*exec.ExitError); ok {
			c.AllocationCommandStatus <- exitErr
		} else {
			log.Error("Could not handle exit error of allocation command: ", e)
			c.AllocationCommandStatus <- e
		}
	}()

	if !c.Allocation.Success {
		_ = c.AllocationCommand.Process.Kill() // nolint: gosec
		if (strings.Contains(c.Allocation.Error, "invalid security groups requested for vpc id")) ||
			(strings.Contains(c.Allocation.Error, "InvalidGroup.NotFound") ||
				(strings.Contains(c.Allocation.Error, "InvalidSecurityGroupID.NotFound"))) {
			var invalidSg runtimeTypes.InvalidSecurityGroupError
			invalidSg.Reason = errors.New(c.Allocation.Error)
			return &invalidSg
		}
		return fmt.Errorf("vpc network configuration error: %s", c.Allocation.Error)
	}

	allocateDone = true
	log.WithField("allocation", c.Allocation).Info("vpc network configuration obtained")

	return nil
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

func (r *DockerRuntime) doSetupMetatronContainer(ctx context.Context, containerName *string) error {
	cfg := &container.Config{
		Hostname: "titus-metatron",
		Volumes: map[string]struct{}{
			"/titus/metatron": {},
		},
		Entrypoint: []string{"/bin/bash"},
		Image:      r.cfg.ContainerMetatronImage,
	}
	hostConfig := &container.HostConfig{
		NetworkMode: "none",
	}

	return r.createVolumeContainer(ctx, containerName, cfg, hostConfig)
}

func (r *DockerRuntime) doSetupSSHdContainer(ctx context.Context, containerName *string) error {
	cfg := &container.Config{
		Hostname: "titus-sshd",
		Volumes: map[string]struct{}{
			"/titus/sshd": {},
		},
		Entrypoint: []string{"/bin/bash"},
		Image:      r.cfg.ContainerSSHDImage,
	}
	hostConfig := &container.HostConfig{
		NetworkMode: "none",
	}

	return r.createVolumeContainer(ctx, containerName, cfg, hostConfig)
}

// createVolumeContainer creates a container to be used as a source for volumes to be mounted via VolumesFrom
func (r *DockerRuntime) createVolumeContainer(ctx context.Context, containerName *string, cfg *container.Config, hostConfig *container.HostConfig) error { // nolint: gocyclo
	image := cfg.Image
	tmpImageInfo, err := imageExists(ctx, r.client, image)
	if err != nil {
		return err
	}

	imageSpecifiedByTag := !strings.Contains(image, "@")
	logger := log.WithField("hostName", cfg.Hostname).WithField("imageName", image)

	if tmpImageInfo == nil || imageSpecifiedByTag {
		logger.WithField("byTag", imageSpecifiedByTag).Info("createVolumeContainer: pulling image")
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
		logger.Info("createVolumeContainer: image exists: not pulling image")
	}

	*containerName = cleanContainerName(cfg.Hostname, image)
	logger = log.WithField("hostName", cfg.Hostname).WithField("imageName", image).WithField("containerName", *containerName)

	// Check if this container exists, if not create it.
	_, err = r.client.ContainerInspect(ctx, *containerName)
	if err == nil {
		logger.Info("createVolumeContainer: container exists: not creating")
		return nil
	}

	if !docker.IsErrNotFound(err) {
		return err
	}

	logger.Info("createVolumeContainer: creating container")
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
func (r *DockerRuntime) Prepare(parentCtx context.Context, c *runtimeTypes.Container, binds []string, startTime time.Time) error { // nolint: gocyclo
	var metatronContainerName string
	var sshdContainerName string
	var volumeContainers []string

	l := log.WithField("taskID", c.TaskID)
	l.WithField("prepareTimeout", r.dockerCfg.prepareTimeout).Info("Preparing container")

	ctx, cancel := context.WithTimeout(parentCtx, r.dockerCfg.prepareTimeout)
	defer cancel()

	var (
		containerCreateBody container.ContainerCreateCreatedBody
		myImageInfo         *types.ImageInspect
		dockerCfg           *container.Config
		hostCfg             *container.HostConfig
		size                int64
	)
	dockerCreateStartTime := time.Now()
	group, errGroupCtx := errgroup.WithContext(ctx)
	err := r.validateEFSMounts(c)
	if err != nil {
		goto error
	}

	group.Go(func() error {
		imageInfo, pullErr := r.DockerPull(errGroupCtx, c)
		if pullErr != nil {
			return pullErr
		}

		if imageInfo == nil {
			inspected, _, inspectErr := r.client.ImageInspectWithRaw(ctx, c.QualifiedImageName())
			if inspectErr != nil {
				l.WithField("imageName", c.QualifiedImageName()).WithError(inspectErr).Errorf("Error inspecting docker image")
				return inspectErr
			}
			imageInfo = &inspected
		}

		size = r.reportDockerImageSizeMetric(c, imageInfo)
		if !r.hasEntrypointOrCmd(imageInfo, c) {
			return NoEntrypointError
		}

		myImageInfo = imageInfo
		return nil
	})

	if shouldStartMetatronSync(&r.cfg, c) {
		group.Go(func() error {
			l.Info("Setting up metatron container")
			mSetupErr := r.doSetupMetatronContainer(ctx, &metatronContainerName)
			if mSetupErr != nil {
				return errors.Wrap(mSetupErr, "Unable to setup metatron container")
			}

			return nil
		})
	}
	if r.cfg.ContainerSSHD {
		group.Go(func() error {
			l.Info("Setting up SSHd container")
			sshdSetuperr := r.doSetupSSHdContainer(ctx, &sshdContainerName)
			if sshdSetuperr != nil {
				return errors.Wrap(sshdSetuperr, "Unable to setup SSHd container")
			}

			return nil
		})
	}

	if r.cfg.UseNewNetworkDriver {
		group.Go(func() error {
			prepareNetworkStartTime := time.Now()
			netErr := prepareNetworkDriver(errGroupCtx, r.dockerCfg, c)
			if netErr == nil {
				r.metrics.Timer("titus.executor.prepareNetworkTime", time.Since(prepareNetworkStartTime), nil)
			}
			return netErr
		})
	} else {
		// Don't call out to network driver for local development
		c.Allocation = vpcTypes.Allocation{
			IPV4Address: "1.2.3.4",
			DeviceIndex: 1,
			Success:     true,
			Error:       "",
			ENI:         "eni-cat-dog",
		}
		l.Info("Mocking networking configuration in dev mode to IP: ", c.Allocation)
	}

	err = group.Wait()
	if err != nil {
		goto error
	}

	if err = setSystemdRunning(l, *myImageInfo, c); err != nil {
		goto error
	}
	binds = append(binds, getLXCFsBindMounts()...)

	if metatronContainerName != "" {
		volumeContainers = append(volumeContainers, metatronContainerName)
	}
	if sshdContainerName != "" {
		volumeContainers = append(volumeContainers, sshdContainerName)
	}

	dockerCfg, hostCfg, err = r.dockerConfig(c, binds, size, volumeContainers)
	if err != nil {
		goto error
	}

	// setupGPU will override the current Volume driver if there is one
	err = r.setupGPU(c, dockerCfg, hostCfg)
	if err != nil {
		goto error
	}

	l.Infof("create with Docker config %#v and Host config: %#v", *dockerCfg, *hostCfg)

	containerCreateBody, err = r.client.ContainerCreate(ctx, dockerCfg, hostCfg, nil, c.TaskID)
	c.SetID(containerCreateBody.ID)

	r.metrics.Timer("titus.executor.dockerCreateTime", time.Since(dockerCreateStartTime), c.ImageTagForMetrics())
	if docker.IsErrImageNotFound(err) {
		return &runtimeTypes.RegistryImageNotFoundError{Reason: err}
	}
	if err != nil {
		goto error
	}
	l = l.WithField("containerID", c.ID)
	l.Info("Container successfully created")

	err = r.createTitusEnvironmentFile(c)
	if err != nil {
		goto error
	}
	l.Info("Titus environment pushed")

	err = r.createTitusContainerConfigFile(c, startTime)
	if err != nil {
		goto error
	}
	l.Info("Titus Configuration pushed")

	err = r.pushEnvironment(c, myImageInfo)
	if err != nil {
		goto error
	}
	l.Info("Titus environment pushed")

error:
	if err != nil {
		log.Error("Unable to create container: ", err)
		r.metrics.Counter("titus.executor.dockerCreateContainerError", 1, nil)
	}
	return err
}

// Creates the file $titusEnvironments/ContainerID.json as a serialized version of the ContainerInfo protobuf struct
// so other systems can load it
func (r *DockerRuntime) createTitusContainerConfigFile(c *runtimeTypes.Container, startTime time.Time) error {
	containerConfigFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.json", c.TaskID))

	cfg, err := c.GetConfig(startTime)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(containerConfigFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644) // nolint: gosec
	if err != nil {
		return err
	}
	defer shouldClose(f)
	c.RegisterRuntimeCleanup(func() error {
		return os.Remove(containerConfigFile)
	})

	return json.NewEncoder(f).Encode(cfg)
}

// Creates the file $titusEnvironments/ContainerID.env filled with newline delimited set of environment variables
func (r *DockerRuntime) createTitusEnvironmentFile(c *runtimeTypes.Container) error {
	envFile := filepath.Join(runtimeTypes.TitusEnvironmentsDir, fmt.Sprintf("%s.env", c.TaskID))
	f, err := os.OpenFile(envFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644) // nolint: gosec
	if err != nil {
		return err
	}
	defer shouldClose(f)
	c.RegisterRuntimeCleanup(func() error {
		return os.Remove(envFile)
	})

	/* writeTitusEnvironmentFile closes the file for us */
	return writeTitusEnvironmentFile(c.Env, f)
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

func (r *DockerRuntime) logDir(c *runtimeTypes.Container) string {
	return filepath.Join(netflixLoggerTempDir(r.cfg, c), "logs")
}

func (r *DockerRuntime) pushEnvironment(c *runtimeTypes.Container, imageInfo *types.ImageInspect) error { // nolint: gocyclo
	var envTemplateBuf, tarBuf bytes.Buffer

	//myImageInfo.Config.Env

	if err := executeEnvFileTemplate(c, imageInfo, &envTemplateBuf); err != nil {
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

	for _, efsMount := range c.TitusInfo.GetEfsConfigInfo() {
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

	return r.client.CopyToContainer(context.TODO(), c.ID, "/", bytes.NewReader(tarBuf.Bytes()), cco)
}

func maybeConvertIntoBadEntryPointError(err error) error {
	if (strings.Contains(err.Error(), "Container command") && strings.Contains(err.Error(), "not found or does not exist.")) ||
		(strings.Contains(err.Error(), "oci runtime error:") && strings.Contains(err.Error(), "executable file not found in $PATH")) ||
		(strings.Contains(err.Error(), "oci runtime error:") && strings.Contains(err.Error(), "no such file or directory")) {
		return &runtimeTypes.BadEntryPointError{Reason: err}
	}

	return err
}

func inferLocalIP(remoteIP *net.UDPAddr) (net.IP, error) {
	addr, err := net.DialUDP("udp4", nil, remoteIP)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	return net.ParseIP(host), nil
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
	remoteIP net.IP
	// What's the route to that? Eventually, we can do multiple IPs in order to QoS EFS access, but let's do that later.
	localIP net.IP
}

func (r *DockerRuntime) processEFSMounts(c *runtimeTypes.Container) ([]efsMountInfo, error) {
	efsMountInfos := []efsMountInfo{}
	for _, configInfo := range c.TitusInfo.GetEfsConfigInfo() {
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
		// Get the remote IP. -- Is this really the best way how? Go doesn't have a simpler API for this?
		emi.hostname = fmt.Sprintf("%s.efs.%s.amazonaws.com", emi.efsFsID, r.awsRegion)
		// According to go's documentation:
		// Resolving a hostname is not recommended because this returns at most one of its IP addresses.
		// It just takes the first IP the resolver returns
		addr, err := net.ResolveUDPAddr("udp4", emi.hostname+":1")
		if err != nil {
			return nil, err
		}

		// In the "official" go code, they use the first IP returned, but not sure what to do here.
		emi.remoteIP = addr.IP
		emi.localIP, err = inferLocalIP(addr)
		if err != nil {
			return nil, err
		}
		efsMountInfos = append(efsMountInfos, emi)
	}

	return efsMountInfos, nil
}

func (r *DockerRuntime) waitForTini(ctx context.Context, listener *net.UnixListener, efsMountInfos []efsMountInfo, c *runtimeTypes.Container) (string, error) {
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
func (r *DockerRuntime) Start(parentCtx context.Context, c *runtimeTypes.Container) (string, *runtimeTypes.Details, <-chan runtimeTypes.StatusMessage, error) {
	ctx, cancel := context.WithTimeout(parentCtx, r.dockerCfg.startTimeout)
	defer cancel()
	var err error
	var listener *net.UnixListener
	var details *runtimeTypes.Details
	statusMessageChan := make(chan runtimeTypes.StatusMessage, 10)

	entry := log.WithField("taskID", c.TaskID)
	entry.Info("Starting")
	efsMountInfos, err := r.processEFSMounts(c)
	if err != nil {
		return "", nil, statusMessageChan, err
	}

	// This sets up the tini listener. It will autoclose whenever the
	if r.tiniEnabled {
		listener, err = r.setupPreStartTini(ctx, c)
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
	filters.Add("container", c.ID)
	filters.Add("type", "container")

	eventOptions := types.EventsOptions{
		Filters: filters,
	}

	// 1. We need to establish a event channel
	eventChan, eventErrChan := r.client.Events(eventCtx, eventOptions)

	err = r.client.ContainerStart(ctx, c.ID, types.ContainerStartOptions{})
	if err != nil {
		entry.Error("Error starting: ", err)
		r.metrics.Counter("titus.executor.dockerStartContainerError", 1, nil)
		// Check if bad entry point and return specific error
		eventCancel()
		return "", nil, statusMessageChan, maybeConvertIntoBadEntryPointError(err)
	}

	r.metrics.Timer("titus.executor.dockerStartTime", time.Since(dockerStartStartTime), c.ImageTagForMetrics())

	if c.Allocation.IPV4Address == "" {
		log.Fatal("IP allocation unset")
	}
	details = &runtimeTypes.Details{
		IPAddresses: map[string]string{
			"nfvpc": c.Allocation.IPV4Address,
		},
		NetworkConfiguration: &runtimeTypes.NetworkConfigurationDetails{
			IsRoutableIP: true,
			IPAddress:    c.Allocation.IPV4Address,
			EniIPAddress: c.Allocation.IPV4Address,
			EniID:        c.Allocation.ENI,
			ResourceID:   fmt.Sprintf("resource-eni-%d", c.Allocation.DeviceIndex-1),
		},
	}

	if r.tiniEnabled {
		logDir, err := r.waitForTini(ctx, listener, efsMountInfos, c)
		if err != nil {
			eventCancel()
		} else {
			go r.statusMonitor(eventCancel, c, eventChan, eventErrChan, statusMessageChan)
		}
		return logDir, details, statusMessageChan, err
	}

	go r.statusMonitor(eventCancel, c, eventChan, eventErrChan, statusMessageChan)
	// We already logged above that we aren't using Tini
	// This means that the log watcher is not started
	return "", details, statusMessageChan, nil
}

func (r *DockerRuntime) statusMonitor(cancel context.CancelFunc, c *runtimeTypes.Container, eventChan <-chan events.Message, errChan <-chan error, statusMessageChan chan runtimeTypes.StatusMessage) {
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
func handleEvent(c *runtimeTypes.Container, message events.Message, statusMessageChan chan runtimeTypes.StatusMessage) bool {
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
			Msg:    fmt.Sprintf("%s exited due to OOMKilled", c.TaskID),
		}
		// Ignore exec events entirely
	case "exec_create", "exec_start", "exec_die":
		return false
	default:
		log.WithField("taskID", c.ID).Info("Received unexpected event: ", message)
		return false
	}

	return true
}

// The only purpose of this is to test the sanity of our filters, and Docker
func validateMessage(c *runtimeTypes.Container, message events.Message) {
	if c.ID != message.ID {
		panic(fmt.Sprint("c.ID != message.ID: ", message))
	}
	if message.Type != "container" {
		panic(fmt.Sprint("message.Type != container: ", message))
	}
}

const (
	// MS_RDONLY indicates that mount is read-only
	MS_RDONLY = 1 // nolint: golint
	// MS_MGC_VAL does nothing, it's just a non-0 value that used to be legacy in the kernel to indicate mount options
	MS_MGC_VAL = 0xC0ED0000 // nolint: golint
)

func (r *DockerRuntime) setupEFSMounts(parentCtx context.Context, c *runtimeTypes.Container, rootFile *os.File, cred *ucred, efsMountInfos []efsMountInfo) error {
	baseMountOptions := []string{"vers=4.1,nosharecache,rsize=1048576,wsize=1048576,timeo=600,retrans=2,noresvport"}

	mntNSPath := filepath.Join("/proc", strconv.Itoa(int(cred.pid)), "ns", "mnt")
	mntNSFile, err := os.OpenFile(mntNSPath, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer shouldClose(mntNSFile)

	netNSPath := filepath.Join("/proc", strconv.Itoa(int(cred.pid)), "ns", "net")
	netNSFile, err := os.OpenFile(netNSPath, os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	defer shouldClose(netNSFile)

	for _, efsMountInfo := range efsMountInfos {
		// Todo: Make into a const
		// TODO: Run this under the container's PID namespace
		// Although 5 minutes is probably far too much here, this window is okay to be large
		// because the parent window should be greater
		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/apps/titus-executor/bin/titus-mount") // nolint: gosec
		// mntNSFD = 3+0 = 3
		// userNSFD = 3+1 = 4
		flags := MS_MGC_VAL
		if efsMountInfo.readWriteFlags == ro {
			flags = flags | MS_RDONLY
		}

		cmd.ExtraFiles = []*os.File{mntNSFile, netNSFile}

		mountOptions := append(
			baseMountOptions,
			fmt.Sprintf("addr=%s", efsMountInfo.remoteIP.String()),
			fmt.Sprintf("clientaddr=%s", efsMountInfo.localIP.String()),
			fmt.Sprintf("fsc=%s", c.TaskID),
		)
		cmd.Env = []string{
			// Go-ism
			// If you pass file descriptors over os/cmd, it will be 3+n where N is the index of the file descriptor in the slice you pass.
			// See above for "math"
			"MOUNT_NS=3",
			"NET_NS=4",
			fmt.Sprintf("MOUNT_TARGET=%s", efsMountInfo.cleanMountPoint),
			fmt.Sprintf("MOUNT_SOURCE=%s:%s", efsMountInfo.hostname, efsMountInfo.cleanEfsFsRelativeMntPoint),
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
func (r *DockerRuntime) setupPreStartTini(ctx context.Context, c *runtimeTypes.Container) (*net.UnixListener, error) {
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

func (r *DockerRuntime) setupPostStartLogDirTini(ctx context.Context, l *net.UnixListener, c *runtimeTypes.Container) (string, *ucred, *os.File, *net.UnixConn, error) {
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

func (r *DockerRuntime) setupPostStartLogDirTiniHandleConnection(parentCtx context.Context, c *runtimeTypes.Container, unixConn *net.UnixConn) (string, *ucred, *os.File, error) {
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

	c.RegisterRuntimeCleanup(func() error {
		shouldClose(unixConn)
		return nil
	})
	if err != nil {
		log.Error("Unable to get FDs from container: ", err)
		return "", nil, nil, err
	}

	rootFile := files[0]

	// r.logDir(c), &cred, rootFile, nil
	err = r.setupPostStartLogDirTiniHandleConnection2(parentCtx, c, cred, rootFile)
	return r.logDir(c), &cred, rootFile, err
}

func (r *DockerRuntime) setupPostStartLogDirTiniHandleConnection2(parentCtx context.Context, c *runtimeTypes.Container, cred ucred, rootFile *os.File) error { // nolint: gocyclo
	group, errGroupCtx := errgroup.WithContext(parentCtx)

	if r.cfg.UseNewNetworkDriver && c.Allocation.IPV4Address != "" {
		group.Go(func() error {
			return setupNetworking(r.dockerCfg.burst, c, cred)
		})
	}

	if r.dockerCfg.enableTitusIsolateBlock {
		group.Go(func() error {
			waitForTitusIsolate(errGroupCtx, c.TaskID, r.dockerCfg.titusIsolateBlockTime)
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return err
	}

	if r.dockerCfg.bumpTiniSchedPriority {
		if err := setupScheduler(cred); err != nil {
			return err
		}
	}

	if err := setupOOMAdj(c, cred); err != nil {
		return err
	}

	if err := setCgroupOwnership(parentCtx, c, cred); err != nil {
		log.WithError(err).Error("Unable to change cgroup ownership")
		return err
	}

	/* This can be "broken" if the titus-executor crashes. The link will be dangling, and point to a
	 * /proc/${PID}/fd/${FD}. It's not "bad", because Titus Task names should be unique
	 */
	pid := os.Getpid()
	logsRoot := filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(int(rootFile.Fd())))
	darionRoot := netflixLoggerTempDir(r.cfg, c)
	if err := os.Symlink(logsRoot, darionRoot); err != nil {
		log.Warning("Unable to setup symlink for darion: ", err)
		return err
	}

	c.RegisterRuntimeCleanup(rootFile.Close)
	c.RegisterRuntimeCleanup(func() error {
		return os.Remove(darionRoot)
	})

	if err := setupSystemPods(parentCtx, c, r.cfg, cred); err != nil {
		log.Warning("Unable to launch pod: ", err)
		return err
	}
	return nil
}

func setupNetworkingArgs(burst bool, c *runtimeTypes.Container) []string {
	bw := uint64(c.BandwidthLimitMbps) * 1000 * 1000
	if bw == 0 {
		bw = defaultNetworkBandwidth
	}
	args := []string{
		"setup-container",
		"--bandwidth", strconv.FormatUint(bw, 10),
		"--netns", "3",
	}
	if burst || c.TitusInfo.GetAllowNetworkBursting() {
		args = append(args, "--burst")
	}
	if jumbo, ok := c.TitusInfo.GetPassthroughAttributes()[jumboFrameParam]; ok {
		if val, err := strconv.ParseBool(jumbo); err != nil {
			log.Error("Could not parse value for "+jumboFrameParam+": ", err)
		} else if val {
			args = append(args, "--jumbo")
		}
	}
	return args
}

func setupNetworking(burst bool, c *runtimeTypes.Container, cred ucred) error { // nolint: gocyclo
	log.Info("Setting up container network")
	var result vpcTypes.WiringStatus

	netnsFile, err := os.Open(filepath.Join("/proc/", strconv.Itoa(int(cred.pid)), "ns", "net"))
	if err != nil {
		return err
	}
	defer shouldClose(netnsFile)

	// This ctx isn't directly descendant from the parent context. It'll be called iff the command successfully starts
	// in the runtime cleanup function, or in
	ctx, cancel := context.WithCancel(context.Background()) // nolint: vet

	c.SetupCommand = exec.CommandContext(ctx, vpcToolPath(), setupNetworkingArgs(burst, c)...) // nolint: gosec
	c.SetupCommandStatus = make(chan error)
	stdin, err := c.SetupCommand.StdinPipe()
	if err != nil {
		return err // nolint: vet
	}
	stdout, err := c.SetupCommand.StdoutPipe()
	if err != nil {
		return err
	}
	c.SetupCommand.Stderr = os.Stderr
	c.SetupCommand.ExtraFiles = []*os.File{netnsFile}

	err = c.SetupCommand.Start()
	if err != nil {
		return err
	}

	c.RegisterRuntimeCleanup(func() error {
		defer cancel()
		_ = c.SetupCommand.Process.Signal(unix.SIGTERM) // nolint: gosec
		time.AfterFunc(1*time.Minute, cancel)
		select {
		case e, ok := <-c.SetupCommandStatus:
			if !ok {
				return nil
			}
			return e
		case <-ctx.Done():
			return fmt.Errorf("Setup Command: %s", ctx.Err().Error())
		}
	})

	go func() {
		defer close(c.SetupCommandStatus)
		e := c.SetupCommand.Wait()
		if e == nil {
			return
		}
		e = ctx.Err()
		if e != nil {
			log.WithError(e).Info("Setup command canceled")
			return
		}
		if exitErr, ok := e.(*exec.ExitError); ok {
			c.SetupCommandStatus <- exitErr
		} else {
			log.Error("Could not handle exit error of setup command: ", e)
			c.SetupCommandStatus <- e
		}
	}()

	cancelTimer := time.AfterFunc(5*time.Minute, func() {
		log.Warning("timed out trying to setup container network")
		cancel()
	})
	if err := json.NewEncoder(stdin).Encode(c.Allocation); err != nil {
		cancel()
		return err
	}
	if err := json.NewDecoder(stdout).Decode(&result); err != nil {
		cancel()
		return fmt.Errorf("Unable to read json from pipe during setup-container: %+v", err)
	}
	if !cancelTimer.Stop() {
		return errors.New("Race condition experienced with container network setup")
	}
	if !result.Success {
		cancel()
		return fmt.Errorf("Network setup error: %s", result.Error)
	}

	return nil
}

func launchTini(conn *net.UnixConn) error {
	// This should be non-blocking
	_, err := conn.Write([]byte{'L'}) // L is for Launch
	return err
}

// setupGPU overrides the volume driver in the provided configuration when there are GPUs to be added to the Container.
func (r *DockerRuntime) setupGPU(c *runtimeTypes.Container, dockerCfg *container.Config, hostCfg *container.HostConfig) error {
	// Setup GPU
	if c.TitusInfo.GetNumGpus() <= 0 {
		return nil
	}

	gpuInfo, err := nvidia.NewNvidiaInfo(r.client)
	if err != nil {
		return err
	}
	// Use nvidia volume plugin that will mount the appropriate
	// libraries/binaries into the container based on host nvidia driver.

	for _, volume := range gpuInfo.Volumes {
		parts := strings.Split(volume, ":")
		dockerCfg.Volumes[parts[1]] = struct{}{}
		hostCfg.Binds = append(hostCfg.Binds, volume)
	}

	// Add control devices to container.
	for _, ctrlDevice := range gpuInfo.GetCtrlDevices() {
		hostCfg.Devices = append(hostCfg.Devices, container.DeviceMapping{
			PathOnHost:        ctrlDevice,
			PathInContainer:   ctrlDevice,
			CgroupPermissions: "rmw",
		})
	}

	// Allocate a specific GPU to add to the container
	c.GPUInfo, err = gpuInfo.AllocDevices(int(c.TitusInfo.GetNumGpus()))
	if err != nil {
		return fmt.Errorf("Cannot allocate %d requested GPU device: %v", c.TitusInfo.GetNumGpus(), err)
	}

	log.Printf("Allocated %d GPU devices %s for task %s", c.TitusInfo.GetNumGpus(), c.GPUInfo, c.TaskID)
	for _, gpuDevicePath := range c.GPUInfo.Devices() {
		hostCfg.Devices = append(hostCfg.Devices, container.DeviceMapping{
			PathOnHost:        gpuDevicePath,
			PathInContainer:   gpuDevicePath,
			CgroupPermissions: "rmw",
		})
	}
	return nil
}

// Kill uses the Docker API to terminate a container and notifies the VPC driver to tear down its networking
func (r *DockerRuntime) Kill(c *runtimeTypes.Container) error { // nolint: gocyclo
	log.Infof("Killing %s", c.TaskID)

	var errs *multierror.Error

	containerStopTimeout := time.Second * time.Duration(c.TitusInfo.GetKillWaitSeconds())
	if containerStopTimeout == 0 {
		containerStopTimeout = defaultKillWait
	}

	if containerJSON, err := r.client.ContainerInspect(context.TODO(), c.ID); docker.IsErrContainerNotFound(err) {
		goto stopped
	} else if err != nil {
		log.Error("Failed to inspect container: ", err)
		errs = multierror.Append(errs, err)
		// There could be a race condition here, where if the container is killed before it is started, it could go into a wonky state
	} else if !containerJSON.State.Running {
		goto stopped
	}

	if err := r.client.ContainerStop(context.TODO(), c.ID, &containerStopTimeout); err != nil {
		r.metrics.Counter("titus.executor.dockerStopContainerError", 1, nil)
		log.Errorf("container %s : stop %v", c.TaskID, err)
		errs = multierror.Append(errs, err)
	} else {
		goto stopped
	}

	if err := r.client.ContainerKill(context.TODO(), c.ID, "SIGKILL"); err != nil {
		r.metrics.Counter("titus.executor.dockerKillContainerError", 1, nil)
		log.Errorf("container %s : kill %v", c.TaskID, err)
		errs = multierror.Append(errs, err)
	}

stopped:
	if c.SetupCommand != nil && c.SetupCommand.Process != nil {
		_ = c.SetupCommand.Process.Signal(unix.SIGTERM) // nolint: gosec
	}
	if c.AllocationCommand != nil {
		if c.AllocationCommand.Process != nil {
			_ = c.AllocationCommand.Process.Signal(unix.SIGTERM) // nolint: gosec
			time.AfterFunc(5*time.Second, func() {
				_ = c.AllocationCommand.Process.Kill() // nolint: gosec
			})
		}

		log.WithField("taskId", c.TaskID).Info("Waiting for deallocation to finish")
		_ = c.AllocationCommand.Wait() // nolint: gosec
		log.WithField("taskId", c.TaskID).Info("Deallocation finished")
	} else {
		log.WithField("taskId", c.TaskID).Info("No need to deallocate, no allocation command")
	}

	if c.TitusInfo.GetNumGpus() > 0 {
		numDealloc := c.GPUInfo.Deallocate()
		log.Infof("Deallocated %d GPU devices for task %s", numDealloc, c.TaskID)
	}

	return errs.ErrorOrNil()
}

// Cleanup runs the registered callbacks for a container
func (r *DockerRuntime) Cleanup(c *runtimeTypes.Container) error {
	var errs *multierror.Error

	cro := types.ContainerRemoveOptions{
		RemoveVolumes: true,
		RemoveLinks:   false,
		Force:         true,
	}

	if err := r.client.ContainerRemove(context.TODO(), c.ID, cro); err != nil {
		r.metrics.Counter("titus.executor.dockerRemoveContainerError", 1, nil)
		log.Errorf("Failed to remove container '%s' with ID: %s: %v", c.TaskID, c.ID, err)
		errs = multierror.Append(errs, err)
	}

	errs = multierror.Append(errs, c.RuntimeCleanup()...)

	return errs.ErrorOrNil()
}

// reportDockerImageSizeMetric reports a metric that represents the container image's size
func (r *DockerRuntime) reportDockerImageSizeMetric(c *runtimeTypes.Container, imageInfo *types.ImageInspect) int64 {
	// reporting image size in KB
	r.metrics.Gauge("titus.executor.dockerImageSize", int(imageInfo.Size/KB), c.ImageTagForMetrics())
	return imageInfo.Size
}

// hasEntrypointOrCmd checks if the image has a an entrypoint, or if we were passed one
func (r *DockerRuntime) hasEntrypointOrCmd(imageInfo *types.ImageInspect, c *runtimeTypes.Container) bool {
	entrypoint, cmd, err := c.Process()
	if err != nil {
		// If this happens, we return true, because this error will bubble up elsewhere
		return true
	}
	return len(entrypoint) > 0 || len(cmd) > 0 || len(imageInfo.Config.Entrypoint) > 0 || len(imageInfo.Config.Cmd) > 0
}

func shouldClose(c io.Closer) {
	if err := c.Close(); err != nil {
		log.Error("Could not close: ", err)
	}
}
