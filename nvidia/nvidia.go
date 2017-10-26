package nvidia

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"context"
	"strings"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	docker "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

const (
	nvidiaPluginURL           = "http://localhost:3476"
	nvidiaPluginDockerJSONURI = "/docker/cli/json"
	nvidiaPluginTimeout       = time.Minute
	nvidiaPluginName          = "nvidia-docker"
)

const (
	// AwsGpuInstanceRegex is a regex that should match AWS GPU instance type strings
	AwsGpuInstanceRegex = "^([g2]|[p2]).[\\S]+"
)

// PluginInfo represents host NVIDIA GPU info
type PluginInfo struct {
	VolumeDriver string   `json:"VolumeDriver"`
	Volumes      []string `json:"Volumes"`
	Devices      []string `json:"Devices"`
	ctrlDevices  []string
	freeDevMap   map[string]string
	dockerClient *docker.Client
	mutex        sync.Mutex
}

// NewNvidiaInfo allocates and initializes NVIDIA info
func NewNvidiaInfo(client *docker.Client) *PluginInfo {
	n := new(PluginInfo)
	n.ctrlDevices = make([]string, 0)
	n.freeDevMap = make(map[string]string)
	n.dockerClient = client

	return n
}

/**
 * Filters GPU devices and control devices in the gpuInfo field.
 */
func (n *PluginInfo) filterGpuInfo() {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	r := regexp.MustCompile(`^/dev/nvidia[\d]+$`)
	for _, device := range n.Devices {
		if r.MatchString(device) {
			// It's GPU device file so add it with no assigned task
			n.freeDevMap[device] = ""
		} else {
			// It's a GPU control file
			n.ctrlDevices = append(n.ctrlDevices, device)
		}
	}
}

// InitHostGpuInfo populates in-mem state about GPU devices and mount info.
func (n *PluginInfo) InitHostGpuInfo() error {
	// Only check if we're on a GPU instance type
	r := regexp.MustCompile(AwsGpuInstanceRegex)
	if !r.MatchString(os.Getenv("EC2_INSTANCE_TYPE")) {
		log.Info("Not on a GPU instance type. No GPU info available.")
		return nil
	}

	// Query GPU info from nvidia docker plugin
	client := http.Client{
		Timeout: nvidiaPluginTimeout,
	}
	resp, err := client.Get(nvidiaPluginURL + nvidiaPluginDockerJSONURI)
	if err != nil {
		return fmt.Errorf("Failed to get GPU info from NVIDIA Docker plugin: %s", err)
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			log.Printf("Failed to close %+v: %s", resp.Body, err)
		}
	}()
	if err = json.NewDecoder(resp.Body).Decode(&n); err != nil {
		return err
	}

	// Make sure we're getting back expected info
	if n.VolumeDriver != nvidiaPluginName {
		return fmt.Errorf("Invalid Nvidia Docker Plugin! Got %s, expected %s", n.VolumeDriver, nvidiaPluginName)
	}
	n.filterGpuInfo()
	log.Infof("On GPU-enabled instance type %s with devices %s", os.Getenv("EC2_INSTANCE_TYPE"), n.Devices)
	return n.wireUpDockerVolume()
}

// wireUpDockerVolume ensures the Docker Volume is created
func (n *PluginInfo) wireUpDockerVolume() error {
	// Fetch the volumes to create from the nVidia Daemon
	volumesToCreate := make(map[string]struct{})
	for _, vol := range n.Volumes {
		volumesToCreate[strings.Split(vol, ":")[0]] = struct{}{}
	}

	// Fetch the volumes that Docker knows about
	args := filters.NewArgs()
	args.Add("driver", n.VolumeDriver)
	volumes, err := n.dockerClient.VolumeList(context.TODO(), args)
	if err != nil {
		return err
	}

	// Determine the volumes that need to be created
	for _, vol := range volumes.Volumes {
		if vol.Driver == n.VolumeDriver {
			delete(volumesToCreate, vol.Name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for vol := range volumesToCreate {
		vcb := volume.VolumesCreateBody{
			Driver:     n.VolumeDriver,
			Name:       vol,
			Labels:     map[string]string{},
			DriverOpts: map[string]string{},
		}
		if err := createVolume(ctx, n.dockerClient, vcb); err != nil {
			return err
		}
	}
	return nil
}

func createVolume(parentCtx context.Context, dockerClient *docker.Client, vcb volume.VolumesCreateBody) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	var err error

	for i := 0; i < 5; i++ {
		_, err = dockerClient.VolumeCreate(ctx, vcb)
		if err == nil {
			return nil
		}
		log.Warningf("Error creating volume %#v: %v", vcb, err)
		time.Sleep(time.Second * 1 << uint(i))
	}
	return err
}

// AllocDevices allocates GPU device names from the free device list for the given task ID.
// Returns an error if no devices are available. If an error is returned,
// the allocation change must not be applied.
func (n *PluginInfo) AllocDevices(taskID string, numDevs uint32) ([]string, error) {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	var allocDevices []string
	for i := uint32(0); i < numDevs; i++ {
		// Find a free device in the device map
		for device := range n.freeDevMap {
			// Check if the device is allocated to a task
			if n.freeDevMap[device] == "" {
				n.freeDevMap[device] = taskID
				allocDevices = append(allocDevices, device)
				break
			}
		}
	}

	// Make sure we allocated the request number of devices. If not,
	// make sure no devices were allocated.
	if uint32(len(allocDevices)) != numDevs {
		for device := range n.freeDevMap {
			if n.freeDevMap[device] == taskID {
				n.freeDevMap[device] = ""
			}
		}
		return nil, fmt.Errorf("Unable able to allocate %d GPU devices. Not enough free GPU devices available", numDevs)
	}

	return allocDevices, nil
}

// DeallocDevice deallocate a task's device.
// An error is returned if the task has no allocated devices.
func (n *PluginInfo) DeallocDevice(taskID string) uint32 {
	numDealloc := uint32(0)
	for dev := range n.freeDevMap {
		if n.freeDevMap[dev] == taskID {
			n.freeDevMap[dev] = ""
			numDealloc++
		}
	}
	return numDealloc
}

// GetCtrlDevices returns the control devices.
func (n *PluginInfo) GetCtrlDevices() []string {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	return n.ctrlDevices
}
