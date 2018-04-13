package nvidia

import (
	"encoding/json"
	"fmt"
	"net/http"

	"regexp"
	"sync"
	"time"

	"context"
	"strings"

	"math/rand"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	docker "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

const (
	nvidiaPluginURL           = "http://localhost:3476"
	nvidiaPluginDockerJSONURI = "/docker/cli/json"
	nvidiaPluginInfoJSONURI   = "/v1.0/gpu/info/json"
	nvidiaPluginTimeout       = time.Minute
	nvidiaPluginName          = "nvidia-docker"
	stateDir                  = "/run/titus-executor-nvidia"
)

const (
	// AwsGpuInstanceRegex is a regex that should match AWS GPU instance type strings
	AwsGpuInstanceRegex = "^([g2]|[p2]).[\\S]+"
)

// NVMLDevice is borrowed from the nvidia-docker 1.0 API
type NVMLDevice struct {
	UUID        string
	Path        string
	Model       *string
	Power       *uint
	CPUAffinity *uint
}

// CUDADevice is borrowed from the nvidia-docker 1.0 API
type CUDADevice struct {
	Family *string
	Arch   *string
	Cores  *uint
}

// Device is borrowed from the nvidia-docker 1.0 API
type Device struct {
	*NVMLDevice
	*CUDADevice
}
type gpuInfo struct {
	// Ignore this field:
	// Version struct{ Driver, CUDA string }
	Devices []Device
}

// PluginInfo represents host NVIDIA GPU info
type PluginInfo struct {
	initOnce                sync.Once
	ctrlDevices             []string
	nvidiaDevices           []string
	dockerClient            *docker.Client
	mutex                   sync.Mutex
	fsLocker                *fslocker.FSLocker
	volumes                 []string
	perTaskAllocatedDevices map[string]map[string]*fslocker.ExclusiveLock
}

type nvidiaDockerCli struct {
	VolumeDriver string   `json:"VolumeDriver"`
	Volumes      []string `json:"Volumes"`
	Devices      []string `json:"Devices"`
}

// NewNvidiaInfo allocates a PluginInfo for NVIDIA. Initialization is done lazily when public methods are called for the
// first time
func NewNvidiaInfo(client *docker.Client) *PluginInfo {
	return &PluginInfo{
		ctrlDevices:             make([]string, 0),
		nvidiaDevices:           make([]string, 0),
		dockerClient:            client,
		perTaskAllocatedDevices: make(map[string]map[string]*fslocker.ExclusiveLock),
	}
}

func (n *PluginInfo) init() (err error) {
	n.initOnce.Do(func() {
		err = n.initHostGpuInfo()
	})
	return
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

// InitHostGpuInfo populates in-mem state about GPU devices and mount info.
func (n *PluginInfo) initHostGpuInfo() error {
	if gpuInstance, err := isGPUInstance(); err != nil {
		return err
	} else if !gpuInstance {
		return nil
	}

	var err error

	n.fsLocker, err = fslocker.NewFSLocker(stateDir)
	if err != nil {
		return err
	}

	// Query GPU info from nvidia docker plugin
	client := &http.Client{
		Timeout: nvidiaPluginTimeout,
	}

	allDevices, err := n.populateAndWireUpvolumes(client)
	if err != nil {
		return err
	}

	return n.gatherDevices(client, allDevices)

}

func (n *PluginInfo) gatherDevices(client *http.Client, allDevices []string) error {
	var info gpuInfo
	allDevicesMap := make(map[string]struct{})
	nonCtrlDevicesMap := make(map[string]struct{})

	for idx := range allDevices {
		allDevicesMap[allDevices[idx]] = struct{}{}
	}

	resp, err := client.Get(nvidiaPluginURL + nvidiaPluginInfoJSONURI)
	if err != nil {
		return fmt.Errorf("Failed to get GPU info from NVIDIA Docker plugin: %s", err)
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			log.Error("Failed to close ", err)
		}
	}()

	if err = json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return err
	}

	for _, device := range info.Devices {
		nonCtrlDevicesMap[device.Path] = struct{}{}
	}

	for dev := range allDevicesMap {
		if _, ok := nonCtrlDevicesMap[dev]; !ok {
			n.ctrlDevices = append(n.ctrlDevices, dev)
		} else {
			n.nvidiaDevices = append(n.nvidiaDevices, dev)
		}
	}

	return nil
}

func (n *PluginInfo) populateAndWireUpvolumes(client *http.Client) ([]string, error) {
	var nvidiaDockerCliResp nvidiaDockerCli

	resp, err := client.Get(nvidiaPluginURL + nvidiaPluginDockerJSONURI)
	if err != nil {
		return nil, fmt.Errorf("Failed to get GPU info from NVIDIA Docker plugin: %s", err)
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			log.Error("Failed to close ", err)
		}
	}()
	if err = json.NewDecoder(resp.Body).Decode(&nvidiaDockerCliResp); err != nil {
		return nil, err
	}

	// Make sure we're getting back expected info
	if nvidiaDockerCliResp.VolumeDriver != nvidiaPluginName {
		return nil, fmt.Errorf("Invalid Nvidia Docker Plugin! Got %s, expected %s", nvidiaDockerCliResp.VolumeDriver, nvidiaPluginName)
	}

	n.volumes = nvidiaDockerCliResp.Volumes

	return nvidiaDockerCliResp.Devices, n.wireUpDockerVolume(nvidiaDockerCliResp.VolumeDriver)
}

// wireUpDockerVolume ensures the Docker Volume is created
func (n *PluginInfo) wireUpDockerVolume(volumeDriver string) error {
	// Fetch the volumes to create from the nVidia Daemon
	volumesToCreate := make(map[string]struct{})
	for _, vol := range n.volumes {
		volumesToCreate[strings.Split(vol, ":")[0]] = struct{}{}
	}

	// Fetch the volumes that Docker knows about
	args := filters.NewArgs()
	args.Add("driver", volumeDriver)
	volumes, err := n.dockerClient.VolumeList(context.TODO(), args)
	if err != nil {
		return err
	}

	// Determine the volumes that need to be created
	for _, vol := range volumes.Volumes {
		if vol.Driver == volumeDriver {
			delete(volumesToCreate, vol.Name)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for vol := range volumesToCreate {
		vcb := volume.VolumesCreateBody{
			Driver:     volumeDriver,
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

func iterOverDevices(devices []string) chan string {
	retChan := make(chan string)
	offset := rand.Int() // nolint: gas

	go func() {
		defer close(retChan)
		for idx := range devices {
			newIdx := (idx + offset) % len(devices)
			retChan <- devices[newIdx]
		}
	}()
	return retChan
}

// AllocDevices allocates GPU device names from the free device list for the given task ID.
// Returns an error if no devices are available. If an error is returned,
// the allocation change must not be applied.
func (n *PluginInfo) AllocDevices(taskID string, numDevs int) ([]string, error) {
	if err := n.init(); err != nil {
		return nil, err
	}

	var lock *fslocker.ExclusiveLock
	var err error
	zeroTimeout := time.Duration(0)
	devices := make([]string, numDevs)
	i := 0

	n.mutex.Lock()
	defer n.mutex.Unlock()

	n.perTaskAllocatedDevices[taskID] = make(map[string]*fslocker.ExclusiveLock)
	for device := range iterOverDevices(n.nvidiaDevices) {
		lock, err = n.fsLocker.ExclusiveLock(device, &zeroTimeout)
		if err == nil && lock != nil {
			n.perTaskAllocatedDevices[taskID][device] = lock
		}
		if len(n.perTaskAllocatedDevices[taskID]) == numDevs {
			goto success
		}
	}
	err = fmt.Errorf("Unable able to allocate %d GPU devices. Not enough free GPU devices available", numDevs)
	goto fail

success:
	for dev := range n.perTaskAllocatedDevices[taskID] {
		devices[i] = dev
		i++
	}
	return devices, nil

fail:
	// Deallocate devices
	for _, lock := range n.perTaskAllocatedDevices[taskID] {
		lock.Unlock()
	}
	delete(n.perTaskAllocatedDevices, taskID)

	return []string{}, err
}

// DeallocDevice deallocate a task's device.
func (n *PluginInfo) DeallocDevice(taskID string) (int, error) {
	if err := n.init(); err != nil {
		return 0, err
	}

	i := 0
	for _, lock := range n.perTaskAllocatedDevices[taskID] {
		lock.Unlock()
		i++
	}
	delete(n.perTaskAllocatedDevices, taskID)

	return i, nil
}

// GetCtrlDevices returns the control devices.
func (n *PluginInfo) GetCtrlDevices() ([]string, error) {
	if err := n.init(); err != nil {
		return nil, err
	}

	return n.ctrlDevices, nil
}

// Volumes returns volumes from the nvidia driver
func (n *PluginInfo) Volumes() ([]string, error) {
	if err := n.init(); err != nil {
		return nil, err
	}
	return n.volumes, nil
}
