package allocate

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/sys/unix"
)

var (
	errIPRefreshFailed         = errors.New("IP refresh failed")
	errMaxIPAddressesAllocated = errors.New("Maximum number of ip addresses allocated")
)

// IPPoolManager encapsulates all management, and locking for a given interface. It must be constructed with NewIPPoolManager
type IPPoolManager struct {
	networkInterface *ec2wrapper.EC2NetworkInterface
}

// NewIPPoolManager sets up an IP pool for this given interface
func NewIPPoolManager(networkInterface *ec2wrapper.EC2NetworkInterface) *IPPoolManager {
	return &IPPoolManager{networkInterface: networkInterface}
}

func (mgr *IPPoolManager) lockConfiguration(parentCtx *context.VPCContext) (*fslocker.ExclusiveLock, error) {
	timeout := time.Minute
	path := filepath.Join(mgr.networkInterface.LockPath(), "ip-config")
	parentCtx.Logger.Debug("Taking exclusive lock for interface reconfiguration: ", path)
	return parentCtx.FSLocker.ExclusiveLock(path, &timeout)
}

func (mgr *IPPoolManager) assignMoreIPs(ctx *context.VPCContext, batchSize int) error {
	if len(mgr.networkInterface.IPv4Addresses) >= vpc.GetMaxIPv4Addresses(ctx.InstanceType) {
		return errMaxIPAddressesAllocated
	}

	if len(mgr.networkInterface.IPv4Addresses)+batchSize > vpc.GetMaxIPv4Addresses(ctx.InstanceType) {
		batchSize = vpc.GetMaxIPv4Addresses(ctx.InstanceType) - len(mgr.networkInterface.IPv4Addresses)
	}

	ctx.Logger.Info("Unable to allocate, no IP addresses available, allocating new IPs")

	// We failed to lock an IP address, let's retry.
	assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             aws.String(mgr.networkInterface.InterfaceID),
		SecondaryPrivateIpAddressCount: aws.Int64(int64(batchSize)),
	}
	_, err := ec2.New(ctx.AWSSession).AssignPrivateIpAddresses(assignPrivateIPAddressesInput)
	if err != nil {
		ctx.Logger.Warning("Unable to assign IPs from AWS: ", err)
		return err
	}

	originalIPCount := len(mgr.networkInterface.IPv4Addresses)
	for i := 0; i < 10; i++ {
		err = mgr.networkInterface.Refresh()
		if err != nil {
			return err
		}
		if len(mgr.networkInterface.IPv4Addresses) > originalIPCount {
			// Retry the allocation
			return nil
		}
		time.Sleep(time.Second)
	}

	ctx.Logger.Warning("Refreshed allocations seconds failed")
	return errIPRefreshFailed
}

func (mgr *IPPoolManager) allocate(ctx *context.VPCContext, batchSize int) (string, *fslocker.ExclusiveLock, error) {
	configLock, err := mgr.lockConfiguration(ctx)
	if err != nil {
		ctx.Logger.Warning("Unable to get lock during allocation: ", err)
		return "", nil, err
	}
	defer configLock.Unlock()

	err = mgr.networkInterface.Refresh()
	if err != nil {
		ctx.Logger.Warning("Unable to refresh interface before attempting to do allocate: ", err)
		return "", nil, err
	}

	ip, lock, err := mgr.doAllocate(ctx)
	// Did we successfully get an IP, or was there an error?
	if err != nil || lock != nil {
		if err != nil {
			ctx.Logger.Warning("Unable to allocate IP: ", err)
		}
		return ip, lock, err
	}

	err = mgr.assignMoreIPs(ctx, batchSize)
	if err != nil {
		ctx.Logger.Warning("Unable assign more IPs: ", err)
		return "", nil, err
	}

	return mgr.doAllocate(ctx)

}

func (mgr *IPPoolManager) doAllocate(ctx *context.VPCContext) (string, *fslocker.ExclusiveLock, error) {
	// Let's see if we can lease a free IP address?
	// Try locking the primary IP address first (always)
	for _, ipAddress := range mgr.networkInterface.IPv4Addresses {
		lock, err := mgr.tryAllocate(ctx, ipAddress)
		if err != nil {
			ctx.Logger.Warning("Unable to do allocation: ", err)
			return "", nil, err
		}
		if lock != nil {
			lock.Bump()
			return ipAddress, lock, nil
		}
	}
	return "", nil, nil
}

func (mgr *IPPoolManager) ipAddressesPath() string {
	return filepath.Join(mgr.networkInterface.LockPath(), "ip-addresses")
}

func (mgr *IPPoolManager) ipAddressPath(ip string) string {
	return filepath.Join(mgr.ipAddressesPath(), ip)
}

func (mgr *IPPoolManager) tryAllocate(ctx *context.VPCContext, ipAddress string) (*fslocker.ExclusiveLock, error) {
	var noTimeout time.Duration
	ipAddressPath := mgr.ipAddressPath(ipAddress)

	// Non-blocking lock
	lock, err := ctx.FSLocker.ExclusiveLock(ipAddressPath, &noTimeout)
	if err != nil && err != unix.EWOULDBLOCK {
		return nil, err
	}

	return lock, nil
}

func (mgr *IPPoolManager) firstPass(parentCtx *context.VPCContext, gracePeriod time.Duration) (fileRemovalList, deallocationList []string, checkIPs map[string]struct{}, retErr error) {
	timeout := 0 * time.Second
	checkIPs = make(map[string]struct{})

	currentlyAssignedIPs := make(map[string]struct{}, len(mgr.networkInterface.IPv4Addresses))
	for _, ip := range mgr.networkInterface.IPv4Addresses {
		currentlyAssignedIPs[ip] = struct{}{}
	}

	records, err := parentCtx.FSLocker.ListFiles(mgr.ipAddressesPath())
	if err != nil {
		retErr = err
		return
	}

	for _, record := range records {
		logEntry := parentCtx.Logger.WithField("ip", record.Name)

		checkIPs[record.Name] = struct{}{}
		// Checks:
		// 1. Is this IP address the primary for this interface?
		if record.Name == mgr.networkInterface.IPv4Addresses[0] {
			continue
		}

		// 2. Has the grace period elapsed for this IP?
		if time.Since(record.BumpTime) < gracePeriod {
			logEntry.WithField("bumpTime", record.BumpTime).Debug("Not GC'ing due to bump time")
			continue
		}

		// 3. Is this IP address in use (can I get an exclusive lock)
		ipAddrLock, err := parentCtx.FSLocker.ExclusiveLock(filepath.Join(mgr.ipAddressesPath(), record.Name), &timeout)
		// Seems like this address is in use
		if err == unix.EWOULDBLOCK {
			logEntry.Debug("File currently locked")
			continue
		} else if err != nil {
			retErr = err
			return
		}
		defer ipAddrLock.Unlock()

		fileRemovalList = append(fileRemovalList, record.Name)
		// 4. Is this IP currently assigned to the interface?
		if _, ok := currentlyAssignedIPs[record.Name]; ok {
			deallocationList = append(deallocationList, record.Name)
		}
	}

	return
}

// DoGc triggers GC for this IP Pool Manager.
func (mgr *IPPoolManager) DoGc(parentCtx *context.VPCContext, gracePeriod time.Duration) error {
	timeout := 0 * time.Second
	lock, err := mgr.lockConfiguration(parentCtx)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	fileRemovalList, deallocationList, checkIPs, err := mgr.firstPass(parentCtx, gracePeriod)
	if err != nil {
		return err
	}

	// If an IP has never been used, IMHO, we should create a record for it, and then the next GC cycle, if it hasn't been
	// used, then we can blow it away
	for _, ip := range mgr.networkInterface.IPv4Addresses {
		logEntry := parentCtx.Logger.WithField("ip", ip)

		if _, ok := checkIPs[ip]; ok {
			continue
		}
		logEntry.Debug("Allocating recording record")
		ipAddrLock, err := parentCtx.FSLocker.ExclusiveLock(filepath.Join(mgr.ipAddressesPath(), ip), &timeout)
		if err == unix.EWOULDBLOCK {
			logEntry.Warning("File currently locked, this should never happen in pass-two")
			continue
		} else if err != nil {
			return err
		}
		// Don't unlock the records until we're done with the GC
		defer ipAddrLock.Unlock()
		ipAddrLock.Bump()
	}
	// At this point it's safe to unlock, unlock is idempotent, so it's safe to call these here
	// we've locked the individual files involved, meaning no one should be able to use those IPs
	// and it's safe the unlock.
	// We unlock here, because in finishGc, it can take quite a while (minutes).
	lock.Unlock()

	return mgr.finishGC(parentCtx, fileRemovalList, deallocationList)
}

func (mgr *IPPoolManager) ipsFreed(parentCtx *context.VPCContext, oldIPList, deallocationList []string) bool {
	for i := 0; i < 30; i++ {
		err := mgr.networkInterface.Refresh()
		if err != nil {
			parentCtx.Logger.Error("Could not refresh IPs: ", err)
		} else {
			allocMap := make(map[string]struct{})
			for _, ip := range mgr.networkInterface.IPv4Addresses {
				allocMap[ip] = struct{}{}
			}

			missingIPs := 0
			for _, oldIP := range oldIPList {
				if _, ok := allocMap[oldIP]; !ok {
					missingIPs++
				}
			}
			if missingIPs > 0 {
				parentCtx.Logger.Infof("%d IPs successfully freed; intended to free: %d", missingIPs, len(deallocationList))
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func (mgr *IPPoolManager) finishGC(parentCtx *context.VPCContext, fileRemovalList, deallocationList []string) error {
	// Prioritize giving IPs back to Amazon
	oldIPList := mgr.networkInterface.IPv4Addresses
	if len(deallocationList) > 0 {
		parentCtx.Logger.Info("Deallocating Ip addresses: ", deallocationList)
		unassignPrivateIPAddressesInput := &ec2.UnassignPrivateIpAddressesInput{
			PrivateIpAddresses: aws.StringSlice(deallocationList),
			NetworkInterfaceId: aws.String(mgr.networkInterface.InterfaceID),
		}

		if _, err := ec2.New(parentCtx.AWSSession).UnassignPrivateIpAddressesWithContext(parentCtx, unassignPrivateIPAddressesInput); err != nil {
			return err
		}

		if !mgr.ipsFreed(parentCtx, oldIPList, deallocationList) {
			parentCtx.Logger.Warning("IP Refresh failed on GC")
		}
	}

	for _, ip := range fileRemovalList {
		if err := parentCtx.FSLocker.RemovePath(filepath.Join(mgr.ipAddressesPath(), ip)); err != nil {
			return err
		}
	}

	return nil
}
