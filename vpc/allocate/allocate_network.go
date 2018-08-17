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
		cli.DurationFlag{
			Name:  "security-convergence-timeout",
			Usage: "How long to wait for security groups to converge, in seconds",
			Value: 10 * time.Second,
		},
		cli.DurationFlag{
			Name:  "wait-for-sg-lock-timeout",
			Usage: "How long to wait for other users, if the SG is in use",
			Value: 0 * time.Second,
		},
		cli.DurationFlag{
			Name:  "ip-refresh-timeout",
			Usage: "How long to wait for AWS to give us IP addresses",
			Value: 10 * time.Second,
		},
		cli.BoolFlag{
			Name:  "allocate-ipv6-address",
			Usage: "Allocate IPv6 Address for container",
		},
	},
}

func getCommandLine(parentCtx *context.VPCContext) (securityGroups map[string]struct{}, batchSize, deviceIdx int, securityConvergenceTimeout, waitForSgLockTimeout, ipRefreshTimeout time.Duration, allocateIPv6Address bool, retErr error) {
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
		return
	}

	securityConvergenceTimeout = parentCtx.CLIContext.Duration("security-convergence-timeout")
	if securityConvergenceTimeout <= 0 {
		retErr = cli.NewExitError("Invalid security convergence timeout", 1)
		return
	}

	waitForSgLockTimeout = parentCtx.CLIContext.Duration("wait-for-sg-lock-timeout")
	if securityConvergenceTimeout < 0 {
		retErr = cli.NewExitError("Invalid securtity group lock timeout", 1)
		return
	}

	ipRefreshTimeout = parentCtx.CLIContext.Duration("ip-refresh-timeout")
	if ipRefreshTimeout < 1*time.Second {
		retErr = cli.NewExitError("IP Refresh timeout must be at least 1 second", 1)
		return
	}
	allocateIPv6Address = parentCtx.CLIContext.Bool("allocate-ipv6-address")

	return
}

func allocateNetwork(parentCtx *context.VPCContext) error {
	var err error

	securityGroups, batchSize, deviceIdx, securityConvergenceTimeout, waitForSgLockTimeout, ipRefreshTimeout, allocateIPv6Address, err := getCommandLine(parentCtx)
	if err != nil {
		return err
	}

	parentCtx.Logger.WithFields(map[string]interface{}{
		"deviceIdx":                  deviceIdx,
		"security-groups":            securityGroups,
		"batch-size":                 batchSize,
		"securityConvergenceTimeout": securityConvergenceTimeout,
		"waitForSgLockTimeout":       waitForSgLockTimeout,
		"ipRefreshTimeout":           ipRefreshTimeout,
		"allocateIPv6Address":        allocateIPv6Address,
	}).Debug()

	allocation, err := doAllocateNetwork(parentCtx, deviceIdx, batchSize, securityGroups, securityConvergenceTimeout, waitForSgLockTimeout, ipRefreshTimeout, allocateIPv6Address)
	if err != nil {
		errors := []error{cli.NewExitError("Unable to setup networking", 1), err}
		err = json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if err != nil {
			errors = append(errors, err)
		}
		return cli.NewMultiError(errors...)
	}
	ctx := parentCtx.WithField("ip4", allocation.ip4Address)
	if allocateIPv6Address {
		ctx = ctx.WithField("ip6", allocation.ip6Address)
	}
	ctx.Logger.Info("Network setup")
	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).
		Encode(
			types.Allocation{
				IPV4Address: allocation.ip4Address,
				IPV6Address: allocation.ip6Address,
				DeviceIndex: deviceIdx,
				Success:     true,
				ENI:         allocation.eni})
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
				ctx.Logger.Error("Unable to refresh IP allocation record: ", err)
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
	sharedSGLock     *fslocker.SharedLock
	exclusiveIP4Lock *fslocker.ExclusiveLock
	exclusiveIP6Lock *fslocker.ExclusiveLock
	ip4Address       string
	ip6Address       string
	eni              string
}

func (a *allocation) refresh() error {
	a.exclusiveIP4Lock.Bump()
	if a.exclusiveIP6Lock != nil {
		a.exclusiveIP6Lock.Bump()
	}
	return nil
}

func (a *allocation) deallocate(ctx *context.VPCContext) {
	a.exclusiveIP4Lock.Unlock()
	if a.exclusiveIP6Lock != nil {
		a.exclusiveIP6Lock.Bump()
	}
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

func doAllocateNetwork(parentCtx *context.VPCContext, deviceIdx, batchSize int, securityGroups map[string]struct{}, securityConvergenceTimeout, waitForSgLockTimeout, ipRefreshTimeout time.Duration, allocateIPv6Address bool) (*allocation, error) {
	// 1. Ensure security groups are setup
	ctx, cancel := parentCtx.WithTimeout(5 * time.Minute)
	defer cancel()

	networkInterface, err := getInterfaceByIdx(ctx, deviceIdx)
	if err != nil {
		ctx.Logger.Warning("Unable to get interface by idx: ", err)
		return nil, err
	}
	allocation := &allocation{
		eni: networkInterface.InterfaceID,
	}
	allocation.sharedSGLock, err = setupSecurityGroups(ctx, networkInterface, securityGroups, securityConvergenceTimeout, waitForSgLockTimeout)
	if err != nil {
		ctx.Logger.Warning("Unable to setup security groups: ", err)
		return nil, err
	}
	// 2. Get a (free) IP
	ipPoolManager := NewIPPoolManager(networkInterface)
	allocation.ip4Address, allocation.exclusiveIP4Lock, err = ipPoolManager.allocateIPv4(ctx, batchSize, ipRefreshTimeout)
	if err != nil {
		return nil, err
	}

	// Optionally, get an IPv6 address
	if allocateIPv6Address {
		allocation.ip6Address, allocation.exclusiveIP6Lock, err = ipPoolManager.allocateIPv6(ctx, networkInterface)
		if err != nil {
			allocation.deallocate(ctx)
			return nil, err
		}
	}

	return allocation, nil
}

func upgradeSecurityGroupLock(networkInterface *ec2wrapper.EC2NetworkInterface, sgConfigurationLock *fslocker.SharedLock, waitForSgLockTimeout time.Duration) (*fslocker.ExclusiveLock, error) {
	sgReconfigurationLock, err := sgConfigurationLock.ToExclusiveLock(&waitForSgLockTimeout)
	if err == nil {
		return sgReconfigurationLock, nil
	}

	sgConfigurationLock.Unlock()
	if err == unix.EWOULDBLOCK {
		return nil, fmt.Errorf("Interface currently in use by other security groups: %v", networkInterface.SecurityGroupIds)
	}

	if err == unix.ETIMEDOUT {
		// Now we fall back
		return nil, fmt.Errorf("Interface currently in use by other security groups: %v, and timed out waiting for other user after %s", networkInterface.SecurityGroupIds, waitForSgLockTimeout.String())
	}

	return nil, err
}

func reconfigureSecurityGroups(ctx *context.VPCContext, networkInterface *ec2wrapper.EC2NetworkInterface, securityGroups map[string]struct{}, sgConfigurationLock *fslocker.SharedLock, securityConvergenceTimeout, waitForSgLockTimeout time.Duration) (*fslocker.SharedLock, error) {
	// If we're supposed to reconfigure security groups, it means no one else should have a lock on the interface
	sgExclusiveReconfigurationLock, err := upgradeSecurityGroupLock(networkInterface, sgConfigurationLock, waitForSgLockTimeout)
	if err != nil {
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
		sgExclusiveReconfigurationLock.Unlock()
		return nil, err
	}
	err = waitForSecurityGroupToConverge(ctx, networkInterface, securityGroups, securityConvergenceTimeout)
	if err != nil {
		ctx.Logger.Warning("Security groups for interface not converged")
		sgExclusiveReconfigurationLock.Unlock()
		return nil, err
	}

	return sgExclusiveReconfigurationLock.ToSharedLock(), nil
}

func setupSecurityGroups(ctx *context.VPCContext, networkInterface *ec2wrapper.EC2NetworkInterface, securityGroups map[string]struct{}, securityConvergenceTimeout, waitForSgLockTimeout time.Duration) (*fslocker.SharedLock, error) {
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
	ctx.Logger.WithField("networkInterface.SecurityGroupIds", networkInterface.SecurityGroupIds).WithField("securityGroups", securityGroups).Debug("Checking security groups")
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
	sharedLock, err := reconfigureSecurityGroups(ctx, networkInterface, securityGroups, sgConfigurationLock, securityConvergenceTimeout, waitForSgLockTimeout)
	if err != nil {
		return nil, err
	}

	return sharedLock, nil
}

func waitForSecurityGroupToConverge(ctx *context.VPCContext, networkInterface *ec2wrapper.EC2NetworkInterface, securityGroups map[string]struct{}, securityConvergenceTimeout time.Duration) error {
	now := time.Now()
	for time.Since(now) < securityConvergenceTimeout {
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
