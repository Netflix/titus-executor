package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Netflix/titus-executor/logger"
)

const (
	ephemeralStorageDeviceFolder = "/dev/ephemeral/"
	mountPathInContainer         = "/ephemeral"
	reservedVGSpaceGB            = 40
)

func ephemeralStorageIsAvailable() bool {
	// This is the simplest way to tell if the VG exists
	// TODO: is there a better way?
	_, err := os.Stat("/etc/lvm/backup/ephemeral")
	return err == nil
}

func ephemeralStorageRunner(ctx context.Context, command string, config EBSMountConfig) error {
	l := logger.GetLogger(ctx)
	var err error
	switch command {
	case "start":
		err = ephemeralStorageStart(ctx, config)
		if err != nil {
			l.Error("Failed to start. Running ephemeral storage stop as we wont get a stop command later on TASK_LOST")
			_ = ephemeralStorageStop(ctx, config)
		}
		return err
	case "stop":
		err = ephemeralStorageStop(ctx, config)
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
	if err != nil {
		return fmt.Errorf("Unable to run command %q: %w", command, err)
	}
	return nil
}

func ephemeralStorageStart(ctx context.Context, config EBSMountConfig) error {
	l := logger.GetLogger(ctx)
	sizeGB, err := getEphemeralStorageSizeGB()
	if err != nil {
		return err
	}
	err = LogicalVolumeCreate(config.taskID, sizeGB)
	if err != nil {
		return err
	}
	device, err := getTaskEphemeralStorageDevice(config.taskID)
	if err != nil {
		return fmt.Errorf("Error when looking up the absolute path of the device %s: %w", device, err)
	}
	err = mkfs(ctx, device, "xfs")
	if err != nil {
		return fmt.Errorf("Error when mkfs.xfs on %s: %w", device, err)
	}
	mc := MountCommand{
		device:     device,
		fstype:     "xfs",
		mountPoint: "/ephemeral",
		perms:      "RW",
		pid1Dir:    config.pid1Dir,
	}
	err = mountBlockDeviceInContainer(ctx, mc)
	if err != nil {
		return err
	}
	l.Infof("Mounted ephemeral storage %s into %s in the container", device, mountPathInContainer)
	return nil
}

func ephemeralStorageStop(ctx context.Context, config EBSMountConfig) error {
	l := logger.GetLogger(ctx)
	device, err := getTaskEphemeralStorageDevice(config.taskID)
	if err != nil {
		return fmt.Errorf("Error when looking up ephemeral storage device: %w", err)
	}
	l.Infof("Cleaned up ephemeral storage '%s'", device)
	return LogicalVolumeRemove(device)
}

func getTaskEphemeralStorageDevice(taskID string) (string, error) {
	relativePath := ephemeralStorageDeviceFolder + taskID
	// LVM provides easy to compute paths, but they are symlinks to the
	// real block device that we need to give ot the mount command.
	return filepath.EvalSymlinks(relativePath)
}

// getEphemeralStorageSizeGB does business logic based on:
// 1. How many GPUs were requested
// 2. How many total GPUs are there?
// 3. How much ephemeral volume do we have
// The theory here is that, if you asked for all the GPUs,
// then you should get all the ephemeral storage (nobody else is using it)
// but if you asked for 1 out of 8 GPUS, then you should get 1/8th of the storage.
// Also accounting for some buffer room in the volume group.
func getEphemeralStorageSizeGB() (int, error) {
	gpusRequested, err := getGpusRequested()
	if err != nil {
		return -1, err
	}
	totalGpus, err := getTotalGpus()
	if err != nil {
		return -1, err
	}
	totalVGSizeGB, err := getTotalVGSizeGB()
	if err != nil {
		return -1, err
	}
	return calculateEphemeralStorageSizeGB(gpusRequested, totalGpus, totalVGSizeGB), nil
}

func calculateEphemeralStorageSizeGB(gpusRequested int, totalGpus int, totalVGSizeGB int) int {
	sizeGB := (float32(gpusRequested) / float32(totalGpus)) * float32((totalVGSizeGB - reservedVGSpaceGB))
	return int(sizeGB)
}

func getGpusRequested() (int, error) {
	requestedGPUString := os.Getenv("TITUS_NUM_GPU")
	if requestedGPUString == "" {
		return 0, fmt.Errorf("TITUS_NUM_GPU not available in the environment. Is this a GPU job?")
	}
	requestedGPU, err := strconv.Atoi(requestedGPUString)
	if err != nil {
		return 0, fmt.Errorf("Error when trying to parse the env variable for TITUS_NUM_GPU: '%s': %w", requestedGPUString, err)
	}
	return requestedGPU, nil
}

func getTotalGpus() (int, error) {
	instanceType := os.Getenv("EC2_INSTANCE_TYPE")
	// It is true that there is an AWS api to retrieve this data
	// but the cost of making an API call in the path of a container startup
	// is too great, compared to the pain of updating this map whenver we
	// add support for a new gpu instance type in Titus (maybe once per year)
	gpuMap := map[string]int{
		"g4dn.metal":   8,
		"g4dn.8xlarge": 1,
		"g4dn.4xlarge": 1,
		"p4d.24xlarge": 8,
	}
	numGpus, ok := gpuMap[instanceType]
	if !ok {
		return -1, fmt.Errorf("Error looking up how many gpus instance type '%s' has", instanceType)
	}
	return numGpus, nil
}

func getTotalVGSizeGB() (int, error) {
	return LogicalVolumeSizeGB(TitusEphemeralVolumeGroup)
}
