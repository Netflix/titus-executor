package nvidia

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
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
	r                     = regexp.MustCompile(AwsGpuInstanceRegex)
)

type gpusNotFoundError struct{}
type gpuQueryTimeoutError struct{}

func (gpusNotFoundError) Error() string    { return "no GPU devices found" }
func (gpuQueryTimeoutError) Error() string { return "timeout querying for GPUs" }

// PluginInfo represents host NVIDIA GPU info
type pluginInfo struct {
	runtime  string
	gpuIds   []string
	mutex    sync.Mutex
	fsLocker *fslocker.FSLocker
}

// NewNvidiaInfo allocates and initializes NVIDIA info
func NewNvidiaInfo(ctx context.Context, runtime string) (types.GPUManager, error) {
	pluginInfo := &pluginInfo{
		runtime: runtime,
	}
	// populate in-mem state about GPU devices
	if gpuInstance, err := isGPUInstance(ctx); err != nil {
		return nil, err
	} else if !gpuInstance {
		return pluginInfo, nil
	}

	var err error
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	pluginInfo.fsLocker, err = fslocker.NewFSLocker(stateDir)
	if err != nil {
		return nil, err
	}

	nvidiaSmiExe, err := exec.LookPath(nvidiaSmiCmd)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, nvidiaSmiTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nvidiaSmiExe, "--query-gpu=gpu_uuid", "--format=csv,noheader")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		log.WithError(err).Errorf("error running nvidia-smi: stdout=%q, stderr=%q", stdout.String(), stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			return nil, GpuQueryTimeout
		}

		return nil, err
	}

	// We should only get to this part if we have found that we're on a GPU instance. Otherwise, the initial test
	// for instance type will short-circuit us from getting to here.
	pluginInfo.gpuIds = strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(pluginInfo.gpuIds) == 0 {
		log.Errorf("nvidia-smi returned 0 devices: stdout=%q, stderr=%q", stdout.String(), stderr.String())
		return nil, NoGpusFound
	}

	return pluginInfo, nil
}

func isGPUInstance(ctx context.Context) (bool, error) {
	// Only check if we're on a GPU instance type
	sess := session.Must(session.NewSession())
	metadatasvc := ec2metadata.New(sess)
	instanceType, err := metadatasvc.GetMetadata("instance-type")
	if err != nil {
		return false, err
	}

	if !r.MatchString(instanceType) {
		logger.G(ctx).Info("Not on a GPU instance type. No GPU info available.")
		return false, nil
	}

	return true, nil
}

// AllocDevices allocates GPU device names from the free device list for the given task ID.
// Returns an error if no devices are available. If an error is returned,
// the allocation change must not be applied.
func (n *pluginInfo) AllocDevices(ctx context.Context, numDevs int) (types.GPUContainer, error) {
	// Either we're on a non-GPU machine (gpuIds is nil), or something else went wrong.
	if len(n.gpuIds) == 0 {
		return nil, NoGpusFound
	}

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
	return &nvidiaGPUContainer{
		allocatedDevices: allocatedDevices,
		runtime:          n.runtime,
	}, nil

fail:
	// Deallocate devices
	for _, lock := range allocatedDevices {
		lock.Unlock()
	}

	return nil, err
}

type nvidiaGPUContainer struct {
	allocatedDevices map[string]*fslocker.ExclusiveLock
	runtime          string
}

func (c *nvidiaGPUContainer) Env() map[string]string {
	return map[string]string{
		// Now setup the environment variables that `nvidia-container-runtime` uses to configure itself,
		// and remove any that may have been set by the user.  See https://github.com/NVIDIA/nvidia-container-runtime
		"NVIDIA_VISIBLE_DEVICES": strings.Join(c.Devices(), ","),

		// nvidia-docker 1.0 would mount all of `/usr/local/nvidia/`, bringing in all of the shared libs.
		// Setting this to "all" will mount all of those libs:
		"NVIDIA_DRIVER_CAPABILITIES": "all",
	}
}

func (c *nvidiaGPUContainer) Runtime() string {
	return c.runtime
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
