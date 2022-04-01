package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/mvisonneau/go-ebsnvme/pkg/ebsnvme"
)

func ebsRunner(ctx context.Context, command string, config MountConfig) error {
	ec2Session := getEC2Session()
	ec2Client := getEc2Client(ec2Session)
	ec2InstanceID := getEC2InstanceID(ec2Session)
	l := logger.GetLogger(ctx)
	var err error

	switch command {
	case "start":
		err = ebsStart(ctx, ec2Client, config, ec2InstanceID)
		if err != nil {
			l.Error("Failed to start. Running stop sequence now as we wont get a stop command later on TASK_LOST")
			_ = ebsStop(ctx, ec2Client, config, ec2InstanceID)
		}
	case "stop":
		err = ebsStop(ctx, ec2Client, config, ec2InstanceID)
	default:
		return fmt.Errorf("Command %q unsupported. Must be either start or stop", command)
	}
	if err != nil {
		return fmt.Errorf("Unable to run command %q: %w", command, err)
	}
	return nil
}

func ebsStart(ctx context.Context, ec2Client *ec2.EC2, c MountConfig, ec2InstanceID string) error {
	var err error
	l := logger.GetLogger(ctx)

	ec2DeviceName, ok := getDeviceName(c.ebsVolumeID)
	if ok {
		l.Printf("EBS volume %s is already attached locally, moving on", c.ebsVolumeID)
	} else {
		err = waitForVolumeToBeUnused(ctx, c.ebsVolumeID, ec2Client, 30)
		if err != nil {
			return fmt.Errorf("%s is not unused. Not safe to detach. %s", c.ebsVolumeID, err)
		}
		ec2DeviceName, err = attachEBS(ctx, c.ebsVolumeID, ec2Client, ec2InstanceID)
		if err != nil {
			return err
		}
	}

	device, err := GetActualBlockDeviceName(ec2DeviceName)
	if err != nil {
		return err
	}

	if c.ebsMountPerm == "RW" {
		// Replicating kubelet behavior, we try to fsck before mount, but if there
		// are errors we try to continue anyway
		fsck(ctx, device, c.ebsFStype)
	}

	mc := MountCommand{
		source:     device,
		fstype:     c.ebsFStype,
		mountPoint: c.ebsMountPoint,
		perms:      c.ebsMountPerm,
		pid1Dir:    c.pid1Dir,
	}
	mountErr := mountBlockDeviceInContainer(ctx, mc)
	if mountErr != nil {
		// Replicating kubelet behavior, it is safer to just try to mount something,
		// and only if it fails do we risk running mkfs and trying again.
		mkfsIsNeeded, mkfsIsNeedederr := isMkfsNeeded(ctx, device, c.ebsFStype)
		if mkfsIsNeedederr != nil {
			return mkfsIsNeedederr
		}
		if mkfsIsNeeded {
			if c.ebsMountPerm != "RW" {
				return fmt.Errorf("A mkfs is needed on this device, but the mount permissions were not RW, they were %q", c.ebsMountPerm)
			}
			l.Infof("mkfs required on %s", device)
			mkfsErr := mkfs(ctx, device, c.ebsFStype)
			if mkfsErr == nil {
				l.Infof("mkfs finished on %s, trying to mount again", device)
				secondMountErr := mountBlockDeviceInContainer(ctx, mc)
				if secondMountErr != nil {
					return fmt.Errorf("Failed to mount a second time, even after a mkfs: %w", secondMountErr)
				}
				l.Infof("finished setting up EBS %s at %s inside the container after mkfs", c.ebsVolumeID, c.ebsMountPoint)
				return nil
			}
			return mkfsErr
		}
		return mountErr
	}
	l.Infof("finished setting up EBS %s at %s inside the container", c.ebsVolumeID, c.ebsMountPoint)
	return nil
}

func ebsStop(ctx context.Context, ec2Client *ec2.EC2, c MountConfig, ec2InstanceID string) error {
	l := logger.GetLogger(ctx)
	ec2Device, ok := getDeviceName(c.ebsVolumeID)
	if !ok {
		l.Printf("EBS volume %s doesn't look attached. Nothing to do", c.ebsVolumeID)
		return nil
	}

	actualDeviceName, err := GetActualBlockDeviceName(ec2Device)
	if err != nil {
		return err
	}

	// Sometimes ebsStop gets called *before* a container dies, so we need to wait.
	// Sometimes ebsStop gets called *after* a container dies, that is fine, will move on quickly
	// *Sometimes* ebsStop gets called *defore* a container dies, but *after* a *different* container
	// comes up, see it is attached, and mounts. In this case we need to still panic here, but it is "ok"
	// In that situation we should not continue to detach a volume out from underneath it
	l.Printf("Waiting up to %d seconds for %s to be not in use...", 60, actualDeviceName)
	err = waitForDeviceToBeNotInUse(actualDeviceName, 60)
	if err != nil {
		return fmt.Errorf("Not detaching volume: %s", err)
	}

	// By the time we get here, we are confident the volume is attached, not in use, and safe to detatch
	err = detatchEBS(ctx, c.ebsVolumeID, ec2Client, ec2InstanceID)
	if err != nil {
		return err
	}
	return nil
}

func getEc2Client(sess *session.Session) *ec2.EC2 {
	return ec2.New(sess)
}

func getEC2InstanceID(sess *session.Session) string {
	mdSvc := ec2metadata.New(sess)
	if !mdSvc.Available() {
		log.Fatal("Metadata service cannot be reached.")
	}
	identify, err := mdSvc.GetInstanceIdentityDocument()
	if err != nil {
		log.Fatalf("Couldn't even get my ec2 instance identify document: %s", err)
	}
	return identify.InstanceID
}

func getEC2Session() *session.Session {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	creds := credentials.NewCredentials(
		&ec2rolecreds.EC2RoleProvider{
			Client:       ec2metadata.New(sess),
			ExpiryWindow: 5 * time.Minute,
		},
	)
	sess.Config.Credentials = creds
	sess.Config.Region = aws.String(os.Getenv("EC2_REGION"))
	return sess
}

func waitForVolumeToBeUnused(ctx context.Context, ebsVolumeID string, ec2Client *ec2.EC2, timeout int) error {
	l := logger.GetLogger(ctx)
	for attempt := 0; attempt < timeout; attempt++ {
		req := ec2.DescribeVolumeStatusInput{
			VolumeIds: []*string{aws.String(ebsVolumeID)},
		}
		response, err := ec2Client.DescribeVolumeStatus(&req)
		if err != nil {
			return err
		}
		if len(response.VolumeStatuses) > 0 {
			s := response.VolumeStatuses[0].VolumeStatus.Status
			if aws.StringValue(s) == "ok" {
				return nil
			}
			l.Printf("Volume Status %+v", *s)
		}
		// This is a simple way to sleep longer and longer each time,
		// to not hammer the aws API
		time.Sleep(time.Duration(attempt) * time.Second)
	}
	return fmt.Errorf("Waited too long for volume to be unused")
}

func randDriveNamePicker() (string, error) {
	deviceName := "/dev/xvd"
	runes := []rune("fghijklmnopqrstuvwxyz")
	for i := 0; i < len(runes); i++ {
		drive := deviceName + string(runes[i])
		if !doesDriveExist(drive) {
			return drive, nil
		}
	}
	return "", errors.New("Ran out of drive names")
}

func doesDriveExist(driveName string) bool {
	if _, err := os.Stat(driveName); os.IsNotExist(err) {
		for _, file := range listNvmeBlockDevices() {
			if d, _ := ebsnvme.ScanDevice(file); d.Name == driveName {
				return true
			}
		}
		return false
	}
	return true
}

// waitForDeviceToDisappear is an inexpensive way to poll for an EBS
// detachment without calling the EC2 API. It does this by waiting
// for the block device it was attached with to dissapear from /dev
func waitForDeviceToDisappear(ctx context.Context, driveName string, maxAttempts int) error {
	start := time.Now()
	l := logger.GetLogger(ctx)
	var attempts int
	for doesDriveExist(driveName) {
		time.Sleep(2 * time.Second)
		attempts++
		if attempts >= maxAttempts {
			elapsed := int(time.Since(start).Seconds())
			return fmt.Errorf("waited the max %d seconds for %s to go, but it is still here", elapsed, driveName)
		}
	}
	elapsed := int(time.Since(start).Seconds())
	l.Printf("waited for %s to disappear, and it is now gone after %d seconds", driveName, elapsed)
	return nil
}

// waitForDriveToExistWithTimeout is an inexpensive way to poll for an EBS
// attachment without calling the EC2 API. It does this by scaning the
// list of nvme volumes on disk and looking at their 'serial number'
func waitForDriveToExistWithTimeout(driveName string, maxAttempts int) error {
	var attempts int
	for !doesDriveExist(driveName) {
		time.Sleep(6 * time.Second)
		attempts++
		if attempts >= maxAttempts {
			return fmt.Errorf("drive %s still does't exist after waiting %d seconds", driveName, attempts*2)
		}
	}
	return nil
}

// GetActualBlockDeviceName returns the actual name of the block device seen
// within the instance, like /dev/nvme1
// This is often different from the ec2 device name, which is usually
// something like /dev/sdx
func GetActualBlockDeviceName(name string) (string, error) {
	for _, device := range listNvmeBlockDevices() {
		if d, _ := ebsnvme.ScanDevice(device); d.Name == name {
			return device, nil
		}
	}
	if _, err := os.Stat(name); os.IsNotExist(err) {
		return "", err
	}
	return name, nil
}

func listNvmeBlockDevices() (devices []string) {
	re := regexp.MustCompile(`(^\/dev\/nvme[0-9]+n1$)`)
	f, _ := filepath.Glob("/dev/nvme*")
	for _, d := range f {
		if re.Match([]byte(d)) {
			devices = append(devices, d)
		}
	}
	return
}

// getDeviceName scans the Nvme on disk and looks at the
// serial numbers of the devices and returns the device name
// (/dev/nmve1). Behaves like a hash get, returning key, ok.
// returning "", false if unfound.
func getDeviceName(ebsVolumeID string) (string, bool) {
	for _, device := range listNvmeBlockDevices() {
		if d, _ := ebsnvme.ScanDevice(device); d.VolumeID == ebsVolumeID {
			return d.Name, true
		}
	}
	return "", false
}

func attachEBS(ctx context.Context, ebsVolumeID string, ec2Client *ec2.EC2, instanceID string) (string, error) {
	l := logger.GetLogger(ctx)
	ec2DeviceName, ok := getDeviceName(ebsVolumeID)
	if ok {
		l.Printf("EBS Volume %s already attached as %s, no need to attach again", ebsVolumeID, ec2DeviceName)
		return ec2DeviceName, nil
	}
	ec2DeviceName, err := randDriveNamePicker()
	if err != nil {
		return "", fmt.Errorf("Couldn't find an unused drive name to give to %s: %s", ebsVolumeID, err)
	}
	attachVolIn := &ec2.AttachVolumeInput{
		Device:     &ec2DeviceName,
		InstanceId: &instanceID,
		VolumeId:   &ebsVolumeID,
	}
	volAttachments, err := ec2Client.AttachVolume(attachVolIn)
	if err != nil {
		return "", err
	}
	l.Printf("volAttachments status after AttachVolume: %+v", volAttachments)
	l.Printf("Now waiting up to 60 seconds for device to exist as ec2Device name %s", ec2DeviceName)
	err = waitForDriveToExistWithTimeout(ec2DeviceName, 10)
	if err != nil {
		return "", err
	}
	l.Printf("%s is now attached and ready to be mounted", ebsVolumeID)
	return ec2DeviceName, nil
}

func detatchEBS(ctx context.Context, ebsVolumeID string, ec2Client *ec2.EC2, instanceID string) error {
	l := logger.GetLogger(ctx)
	deviceName, ok := getDeviceName(ebsVolumeID)
	if !ok {
		l.Printf("volume %s doesn't seem to connected. Not bothering to detach using the AWS API", ebsVolumeID)
	}
	detachVolIn := &ec2.DetachVolumeInput{
		Device:     &deviceName,
		InstanceId: &instanceID,
		VolumeId:   &ebsVolumeID,
	}
	l.Printf("Calling the EC2 API to detach %s from %s", ebsVolumeID, instanceID)
	volAttachment, err := ec2Client.DetachVolume(detachVolIn)
	if err != nil {
		return err
	}
	if *volAttachment.InstanceId != instanceID {
		l.Printf("%+v is reporting a different ec2 instance id than mine, %s, could be a bug?", volAttachment, instanceID)
	}
	if *volAttachment.State != "detaching" {
		l.Printf("%+v is reporting something other than 'detaching' after being ask to detach?", volAttachment)
	} else {
		l.Printf("%s is detaching", ebsVolumeID)
	}
	realDeviceName, err := GetActualBlockDeviceName(deviceName)
	if err != nil {
		return err
	}
	err = waitForDeviceToDisappear(ctx, realDeviceName, 10)
	if err != nil {
		return fmt.Errorf("Timed out waiting for detach of %s to finish!: %s", ebsVolumeID, err)
	}
	l.Printf("Detach of %s done", ebsVolumeID)
	return nil
}
