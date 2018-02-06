package allocate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"time"

	"path/filepath"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/sys/unix"
	"gopkg.in/urfave/cli.v1"
)

var (
	errInterfaceNotFoundAtIndex   = errors.New("Network interface not found at index")
	errSecurityGroupsNotConverged = errors.New("Security groups for interface not converged")
)

var AllocateNetwork = cli.Command{ // nolint: golint
	Name:   "allocate-network",
	Usage:  "Allocate networking for a particular VPC",
	Action: context.WrapFunc(allocateNetwork),
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "device-idx",
			Usage: "The device index to setup, 1-indexed (1 correlates to AWS device 1) -- using device index 0 not allowed",
		},
		cli.StringFlag{
			Name:  "security-groups",
			Usage: "Comma separated list of security groups, defaults to the system's security groups",
		},
		cli.IntFlag{
			Name:  "batch-size",
			Usage: "What sized batch to allocate IP address in",
			Value: 4,
		},
	},
}

func getCommandLine(parentCtx *context.VPCContext) (securityGroups map[string]struct{}, batchSize, deviceIdx int, retErr error) {
	var err error

	deviceIdx = parentCtx.CLIContext.Int("device-idx")
	if deviceIdx <= 0 {
		retErr = cli.NewExitError("device-idx required", 1)
		return
	}

	if sgStringList := parentCtx.CLIContext.String("security-groups"); sgStringList == "" {
		securityGroups, err = getDefaultSecurityGroups(parentCtx)
		if err != nil {
			retErr = cli.NewMultiError(cli.NewExitError("Unable to fetch default security groups required", 1), err)
			return
		}
	} else {
		securityGroups = make(map[string]struct{})
		for _, sgID := range strings.Split(sgStringList, ",") {
			securityGroups[sgID] = struct{}{}
		}
	}

	batchSize = parentCtx.CLIContext.Int("batch-size")
	if batchSize <= 0 {
		retErr = cli.NewExitError("Invalid batchsize", 1)
	}
	return
}

func allocateNetwork(parentCtx *context.VPCContext) error {
	var err error

	securityGroups, batchSize, deviceIdx, err := getCommandLine(parentCtx)
	if err != nil {
		return err
	}

	parentCtx.Logger.WithFields(map[string]interface{}{
		"deviceIdx":       deviceIdx,
		"security-groups": securityGroups,
		"batch-size":      batchSize,
	}).Debug()

	allocation, err := doAllocateNetwork(parentCtx, deviceIdx, batchSize, securityGroups)
	if err != nil {
		errors := []error{cli.NewExitError("Unable to setup networking", 1), err}
		err = json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if err != nil {
			errors = append(errors, err)
		}
		return cli.NewMultiError(errors...)
	}
	ctx := parentCtx.WithField("ip", allocation.ipAddress)
	ctx.Logger.Info("Network setup")
	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).Encode(types.Allocation{IPV4Address: allocation.ipAddress, DeviceIndex: deviceIdx, Success: true, ENI: allocation.eni})
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to write allocation record", 1), err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, unix.SIGTERM, unix.SIGINT)
	ticker := time.NewTicker(vpc.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c:
			goto exit
		case <-ticker.C:
			err = allocation.refresh()
			if err != nil {
				ctx.Logger.Error("Unable to refresh IP allocation record")
			}
		}
	}
exit:
	parentCtx.Logger.Info("Beginning shutdown, and deallocation: ", allocation)

	allocation.deallocate(ctx)
	// TODO: Teardown turned up network namespace
	parentCtx.Logger.Info("Finished shutting down and deallocating")
	return nil
}

type allocation struct {
	sharedSGLock    *fslocker.SharedLock
	exclusiveIPLock *fslocker.ExclusiveLock
	ipAddress       string
	eni             string
}

func (a *allocation) refresh() error {
	a.exclusiveIPLock.Bump()
	return nil
}

func (a *allocation) deallocate(ctx *context.VPCContext) {
	a.exclusiveIPLock.Unlock()
	a.sharedSGLock.Unlock()
}

func getDefaultSecurityGroups(parentCtx *context.VPCContext) (map[string]struct{}, error) {
	primaryInterfaceMac, err := parentCtx.EC2metadataClientWrapper.PrimaryInterfaceMac()
	if err != nil {
		return nil, err
	}
	primaryInterface, err := parentCtx.EC2metadataClientWrapper.GetInterface(primaryInterfaceMac)
	if err != nil {
		return nil, err
	}
	return primaryInterface.SecurityGroupIds, nil
}

func doAllocateNetwork(parentCtx *context.VPCContext, deviceIdx, batchSize int, securityGroups map[string]struct{}) (*allocation, error) {
	// 1. Ensure security groups are setup
	ctx, cancel := parentCtx.WithTimeout(5 * time.Minute)
	defer cancel()

	networkInterface, err := getInterfaceByIdx(ctx, deviceIdx)
	if err != nil {
		ctx.Logger.Warning("Unable to get interface by idx: ", err)
		return nil, err
	}
	sharedSGLock, err := setupSecurityGroups(ctx, networkInterface, securityGroups)
	if err != nil {
		ctx.Logger.Warning("Unable to setup security groups: ", err)
		return nil, err
	}
	// 2. Get a (free) IP
	ip, ipLock, err := NewIPPoolManager(networkInterface).allocate(ctx, batchSize)
	if err != nil {
		return nil, err
	}
	allocation := &allocation{
		sharedSGLock:    sharedSGLock,
		exclusiveIPLock: ipLock,
		ipAddress:       ip,
		eni:             networkInterface.InterfaceID,
	}

	return allocation, nil
}

func reconfigureSecurityGroups(ctx *context.VPCContext, networkInterface *ec2wrapper.EC2NetworkInterface, securityGroups map[string]struct{}, sgConfigurationLock *fslocker.SharedLock) (*fslocker.SharedLock, error) {
	// If we're supposed to reconfigure security groups, it means no one else should have a lock on the interface
	lockFree := 0 * time.Second
	sgReconfigurationLock, err := sgConfigurationLock.ToExclusiveLock(&lockFree)
	if err != nil {
		sgConfigurationLock.Unlock()
		if err == unix.EWOULDBLOCK {
			return nil, fmt.Errorf("Interface currently in use by other security groups: %v", networkInterface.SecurityGroupIds)
		}
		return nil, err
	}

	groups := []*string{}
	for sgID := range securityGroups {
		groups = append(groups, aws.String(sgID))
	}
	modifyNetworkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		NetworkInterfaceId: aws.String(networkInterface.InterfaceID),
		Groups:             groups,
	}

	svc := ec2.New(ctx.AWSSession)
	_, err = svc.ModifyNetworkInterfaceAttributeWithContext(ctx, modifyNetworkInterfaceAttributeInput)
	if err != nil {
		ctx.Logger.Warning("Unable to reconfigure security groups: ", err)
		sgReconfigurationLock.Unlock()
		return nil, err
	}
	err = waitForSecurityGroupToConverge(ctx, networkInterface, securityGroups)
	if err != nil {
		ctx.Logger.Warning("Security groups for interface not converged")
		sgReconfigurationLock.Unlock()
		return nil, err
	}

	return sgReconfigurationLock.ToSharedLock(), nil
}

func setupSecurityGroups(ctx *context.VPCContext, networkInterface *ec2wrapper.EC2NetworkInterface, securityGroups map[string]struct{}) (*fslocker.SharedLock, error) {
	lockTimeout := time.Minute
	maybeReconfigurationLockPath := filepath.Join(networkInterface.LockPath(), "security-group-reconfig")
	maybeReconfigurationLock, err := ctx.FSLocker.ExclusiveLock(maybeReconfigurationLockPath, &lockTimeout)
	if err != nil {
		ctx.Logger.Warning("Unable to get security-group-reconfig lock: ", err)
		return nil, err
	}
	defer maybeReconfigurationLock.Unlock()

	// Although nobody should be holding an exclusive lock on security-group-current-config in the critical section, we
	// should still get the shared lock for safety.
	sgConfigureLockPath := filepath.Join(networkInterface.LockPath(), "security-group-current-config")
	sgConfigurationLock, err := ctx.FSLocker.SharedLock(sgConfigureLockPath, &lockTimeout)
	if err != nil {
		ctx.Logger.Warning("Unable to get security-group-current-config lock: ", err)
		return nil, err
	}
	if reflect.DeepEqual(securityGroups, networkInterface.SecurityGroupIds) {
		return sgConfigurationLock, nil
	}
	err = networkInterface.Refresh()
	if err != nil {
		sgConfigurationLock.Unlock()
		return nil, err
	}
	if reflect.DeepEqual(securityGroups, networkInterface.SecurityGroupIds) {
		return sgConfigurationLock, nil
	}

	ctx.Logger.Info("Reconfiguring security groups")
	sharedLock, err := reconfigureSecurityGroups(ctx, networkInterface, securityGroups, sgConfigurationLock)
	if err != nil {
		return nil, err
	}

	return sharedLock, nil
}

func waitForSecurityGroupToConverge(ctx *context.VPCContext, networkInterface *ec2wrapper.EC2NetworkInterface, securityGroups map[string]struct{}) error {
	for i := 0; i < 10; i++ {
		err := networkInterface.Refresh()
		if err != nil {
			ctx.Logger.Warning("Unable to refresh interface while waiting for security group change, bailing: ", err)
			return err
		}
		if reflect.DeepEqual(securityGroups, networkInterface.SecurityGroupIds) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return errSecurityGroupsNotConverged
}

func getInterfaceByIdx(parentCtx *context.VPCContext, idx int) (*ec2wrapper.EC2NetworkInterface, error) {
	allInterfaces, err := parentCtx.EC2metadataClientWrapper.Interfaces()
	if err != nil {
		return &ec2wrapper.EC2NetworkInterface{}, err
	}

	for _, networkInterface := range allInterfaces {
		if networkInterface.DeviceNumber == idx {
			return &networkInterface, nil
		}
	}

	return &ec2wrapper.EC2NetworkInterface{}, errInterfaceNotFoundAtIndex
}
