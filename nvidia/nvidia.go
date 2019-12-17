package nvidia

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"regexp"
	"sync"
	"time"

	"strings"

	"github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/docker/docker/api/types/container"
	log "github.com/sirupsen/logrus"
)

const (
	stateDir         = "/run/titus-executor-nvidia"
	nvidiaSmiCmd     = "nvidia-smi"
	nvidiaSmiTimeout = 2 * time.Second
)

const (
	// AwsGpuInstanceRegex is a regex that should match AWS GPU instance type strings
	AwsGpuInstanceRegex = "^([g2]|[p2]|[p3]|[g4dn]).[\\S]+"
)

var (
	// NoGpusFound indicates that no GPUs could be found on the system
	NoGpusFound error = gpusNotFoundError{}
	// GpuQueryTimeout indicates a timeout in querying for the system's GPUs
	GpuQueryTimeout error = gpuQueryTimeoutError{}
)

type gpusNotFoundError struct{}
type gpuQueryTimeoutError struct{}

func (gpusNotFoundError) Error() string    { return "no GPU devices found" }
func (gpuQueryTimeoutError) Error() string { return "timeout querying for GPUs" }

// PluginInfo represents host NVIDIA GPU info
type PluginInfo struct {
	gpuIds   []string
	mutex    sync.Mutex
	fsLocker *fslocker.FSLocker
}

// NewNvidiaInfo allocates and initializes NVIDIA info
func NewNvidiaInfo(ctx context.Context) (*PluginInfo, error) {
	n := new(PluginInfo)
	n.gpuIds = []string{}

	return n, n.initHostGpuInfo(ctx)
}

func isGPUInstance() (bool, error) {
	// Only check if we're on a GPU instance type
	sess := session.Must(session.NewSession())
	metadatasvc := ec2metadata.New(sess)
	instanceType, err := metadatasvc.GetMetadata("instance-type")
	if err != nil {
		return false, err
	}

	r := regexp.MustCompile(AwsGpuInstanceRegex)
	if !r.MatchString(instanceType) {
		log.Info("Not on a GPU instance type. No GPU info available.")
		return false, nil
	}

	return true, nil
}

// InitHostGpuInfo populates in-mem state about GPU devices
func (n *PluginInfo) initHostGpuInfo(parentCtx context.Context) error {
	if gpuInstance, err := isGPUInstance(); err != nil {
		return err
	} else if !gpuInstance {
		return nil
	}

	var err error
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	n.fsLocker, err = fslocker.NewFSLocker(stateDir)
	if err != nil {
		return err
	}

	nvidiaSmiExe, err := exec.LookPath(nvidiaSmiCmd)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(parentCtx, nvidiaSmiTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nvidiaSmiExe, "--query-gpu=gpu_uuid", "--format=csv,noheader")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.WithError(err).Errorf("error running nvidia-smi: stdout=%q, stderr=%q", stdout.String(), stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			return GpuQueryTimeout
		}

		return err
	}

	n.gpuIds = strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(n.gpuIds) == 0 {
		log.Errorf("nvidia-smi returned 0 devices: stdout=%q, stderr=%q", stdout.String(), stderr.String())
		return NoGpusFound
	}

	return nil
}

// AllocDevices allocates GPU device names from the free device list for the given task ID.
// Returns an error if no devices are available. If an error is returned,
// the allocation change must not be applied.
func (n *PluginInfo) AllocDevices(ctx context.Context, numDevs int) (types.GPUContainer, error) {
	var lock *fslocker.ExclusiveLock
	var err error
	zeroTimeout := time.Duration(0)

	n.mutex.Lock()
	defer n.mutex.Unlock()

	allocatedDevices := make(map[string]*fslocker.ExclusiveLock, numDevs)
	for _, id := range n.gpuIds {
		lock, err = n.fsLocker.ExclusiveLock(ctx, id, &zeroTimeout)
		if err == nil && lock != nil {
			allocatedDevices[id] = lock
		}

		if len(allocatedDevices) == numDevs {
			goto success
		}
	}

	err = fmt.Errorf("Unable able to allocate %d GPU devices. Not enough free GPU devices available", numDevs)
	goto fail

success:
	return &nvidiaGPUContainer{allocatedDevices: allocatedDevices}, nil

fail:
	// Deallocate devices
	for _, lock := range allocatedDevices {
		lock.Unlock()
	}

	return nil, err
}

// UpdateContainerConfig updates the container and host configs to delegate the given devices
func (n *PluginInfo) UpdateContainerConfig(c *types.Container, dockerCfg *container.Config, hostCfg *container.HostConfig, runtime string) {
	hostCfg.Runtime = runtime
	c.Runtime = runtime
	c.Env[types.TitusRuntimeEnvVariableName] = runtime

	// Now setup the environment variables that `nvidia-container-runtime` uses to configure itself,
	// and remove any that may have been set by the user.  See https://github.com/NVIDIA/nvidia-container-runtime
	c.Env["NVIDIA_VISIBLE_DEVICES"] = strings.Join(c.GPUInfo.Devices(), ",")
	// nvidia-docker 1.0 would mount all of `/usr/local/nvidia/`, bringing in all of the shared libs.
	// Setting this to "all" will mount all of those libs:
	c.Env["NVIDIA_DRIVER_CAPABILITIES"] = "all"
	dockerCfg.Env = c.GetSortedEnvArray()
}

type nvidiaGPUContainer struct {
	allocatedDevices map[string]*fslocker.ExclusiveLock
}

func (c *nvidiaGPUContainer) Devices() []string {
	devices := make([]string, 0, len(c.allocatedDevices))
	for key := range c.allocatedDevices {
		devices = append(devices, key)
	}
	return devices
}

func (c *nvidiaGPUContainer) Deallocate() int {
	allocatedCount := len(c.allocatedDevices)
	for _, lock := range c.allocatedDevices {
		lock.Unlock()
	}
	return allocatedCount
}
