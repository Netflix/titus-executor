package allocate

import (
	"errors"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"golang.org/x/sys/unix"
)

var (
	errIPRefreshFailed         = errors.New("IP refresh failed")
	errMaxIPAddressesAllocated = errors.New("Maximum number of ip addresses allocated")
	errNoFreeIPAddressFound    = errors.New("No free IP address found")
)

// IPPoolManager encapsulates all management, and locking for a given interface. It must be constructed with NewIPPoolManager
type IPPoolManager struct {
	networkInterface       ec2wrapper.NetworkInterface
	ipRefreshSleepInterval time.Duration
}

// NewIPPoolManager sets up an IP pool for this given interface
func NewIPPoolManager(networkInterface ec2wrapper.NetworkInterface) *IPPoolManager {
	return &IPPoolManager{
		networkInterface:       networkInterface,
		ipRefreshSleepInterval: 5 * time.Second,
	}
}

func (mgr *IPPoolManager) lockConfiguration(parentCtx *context.VPCContext) (*fslocker.ExclusiveLock, error) {
	timeout := time.Minute
	path := filepath.Join(ec2wrapper.GetLockPath(mgr.networkInterface), "ip-config")
	parentCtx.Logger.Debug("Taking exclusive lock for interface reconfiguration: ", path)
	return parentCtx.FSLocker.ExclusiveLock(path, &timeout)
}

// returns number of refreshes done, and error
func assignMoreIPs(ctx *context.VPCContext, batchSize int, ipRefreshTimeout time.Duration, networkInterface ec2wrapper.NetworkInterface, ipAssignmentFunction ec2wrapper.IPAssignmentFunction, ipFetchFunction ec2wrapper.IPFetchFunction) (int, error) {
	if len(ipFetchFunction()) >= vpc.GetMaxIPAddresses(ctx.InstanceType) {
		return 0, errMaxIPAddressesAllocated
	}

	if len(ipFetchFunction())+batchSize > vpc.GetMaxIPAddresses(ctx.InstanceType) {
		batchSize = vpc.GetMaxIPAddresses(ctx.InstanceType) - len(ipFetchFunction())
	}

	ctx.Logger.Info("Unable to allocate, no IP addresses available, allocating new IPs")

	originalIPSet := ec2wrapper.GetIPAddressesAsSet(ipFetchFunction)

	if err := ipAssignmentFunction(ctx, ctx.AWSSession, batchSize); err != nil {
		ctx.Logger.Warning("Unable to assign IPs from AWS: ", err)
		return 0, err
	}

	now := time.Now()
	i := 0
	for time.Since(now) < ipRefreshTimeout {
		if err := networkInterface.Refresh(ctx, ctx.AWSSession); err != nil {
			return i, err
		}
		i++

		newIPSet := ec2wrapper.GetIPAddressesAsSet(ipFetchFunction)

		if len(newIPSet.Difference(originalIPSet).ToSlice()) > 0 {
			// Retry allocating an IP Address from the pool, now that the metadata service says that we have at
			// least one more IP available from EC2
			return i, nil
		}
		time.Sleep(time.Second)
	}

	ctx.Logger.Warning("Refreshed allocations seconds failed")
	return i, errIPRefreshFailed
}

func (mgr *IPPoolManager) allocateIPv6(ctx *context.VPCContext, batchSize int, ipRefreshTimeout time.Duration) (string, *fslocker.ExclusiveLock, error) {
	return mgr.allocateIP(ctx, batchSize, ipRefreshTimeout, mgr.networkInterface.AddIPv6Addresses, mgr.networkInterface.GetIPv6Addresses)
}

func (mgr *IPPoolManager) allocateIPv4(ctx *context.VPCContext, batchSize int, ipRefreshTimeout time.Duration) (string, *fslocker.ExclusiveLock, error) {
	return mgr.allocateIP(ctx, batchSize, ipRefreshTimeout, mgr.networkInterface.AddIPv4Addresses, mgr.networkInterface.GetIPv4Addresses)
}

func (mgr *IPPoolManager) allocateIP(ctx *context.VPCContext, batchSize int, ipRefreshTimeout time.Duration, ipAssignmentFunction ec2wrapper.IPAssignmentFunction, ipFetchFunction ec2wrapper.IPFetchFunction) (string, *fslocker.ExclusiveLock, error) {
	configLock, err := mgr.lockConfiguration(ctx)
	if err != nil {
		ctx.Logger.Warning("Unable to get lock during allocation: ", err)
		return "", nil, err
	}
	defer configLock.Unlock()

	err = mgr.networkInterface.Refresh(ctx, ctx.AWSSession)
	if err != nil {
		ctx.Logger.Warning("Unable to refresh interface before attempting to do allocate: ", err)
		return "", nil, err
	}

	ip, lock, err := mgr.doAllocate(ctx, ipFetchFunction)
	if err == nil {
		if lock == nil {
			ctx.Logger.Fatal("Err is nil, but lock is nil too")
		}
		ctx.Logger.WithField("ip", ip).Debug("Successfully allocated IP")
		return ip, lock, err
	} else if err == errNoFreeIPAddressFound {
		ctx.Logger.Info("No free IP addresses available, trying to assign more")
		now := time.Now()
		n, err2 := assignMoreIPs(ctx, batchSize, ipRefreshTimeout, mgr.networkInterface, ipAssignmentFunction, ipFetchFunction)
		if err2 != nil {
			ctx.Logger.WithField("duration", time.Since(now)).WithError(err).Warning("Unable assign more IPs")
			return "", nil, err2
		}
		ctx.Logger.WithField("duration", time.Since(now)).WithField("refreshes", n).Info("Successfully completed IP allocation")
		return mgr.doAllocate(ctx, ipFetchFunction)
	}

	return "", nil, err
}

func (mgr *IPPoolManager) doAllocate(ctx *context.VPCContext, ipFetchFunction ec2wrapper.IPFetchFunction) (string, *fslocker.ExclusiveLock, error) {
	// Let's see if we can lease a free IP address?
	// Try locking the primary IP address first (always)
	ips := ipFetchFunction()
	ctx.Logger.WithField("ips", ips).Debug("Trying to allocate IP")
	for _, ipAddress := range ips {
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
	return "", nil, errNoFreeIPAddressFound
}

func (mgr *IPPoolManager) ipAddressesPath() string {
	return filepath.Join(ec2wrapper.GetLockPath(mgr.networkInterface), "ip-addresses")
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

func (mgr *IPPoolManager) firstPass(parentCtx *context.VPCContext, gracePeriod time.Duration) (deallocationList []string, locks []*fslocker.ExclusiveLock, retErr error) {
	timeout := 0 * time.Second
	recordsDict := make(map[string]fslocker.Record)
	locks = []*fslocker.ExclusiveLock{}

	records, err := parentCtx.FSLocker.ListFiles(mgr.ipAddressesPath())
	if err != nil {
		retErr = err
		return
	}
	for _, record := range records {
		recordsDict[record.Name] = record
	}

	// the first IP is always the primary IP on the interface, therefore it shouldn't be tested for removal
	for _, ip := range mgr.networkInterface.GetIPv4Addresses()[1:] {
		logEntry := parentCtx.Logger.WithField("ip", ip)
		logEntry.Debug("Checking IP address")

		// Checks:
		ipAddrLock, err := parentCtx.FSLocker.ExclusiveLock(filepath.Join(mgr.ipAddressesPath(), ip), &timeout)
		// Seems like this address is in use
		if err == unix.EWOULDBLOCK {
			logEntry.Debug("File currently locked")
			continue
		} else if err != nil {
			retErr = err
			for _, lock := range locks {
				lock.Unlock()
			}
			return
		}
		if record, ok := recordsDict[ip]; !ok {
			logEntry.Debug("Did not have existing record / lock")
			ipAddrLock.Unlock()
			continue
		} else if time.Since(record.BumpTime) < gracePeriod {
			logEntry.WithField("timeSinceBumpTime", time.Since(record.BumpTime)).Debug("IP not idle long enough")
			ipAddrLock.Unlock()
			continue
		}
		ipAddrLock.Bump()
		locks = append(locks, ipAddrLock)
		deallocationList = append(deallocationList, ip)
	}

	return
}

// DoGc triggers GC for this IP Pool Manager.
func (mgr *IPPoolManager) DoGc(parentCtx *context.VPCContext, gracePeriod time.Duration) error {
	lock, err := mgr.lockConfiguration(parentCtx)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	deallocationList, locks, err := mgr.firstPass(parentCtx, gracePeriod)
	if err != nil {
		return err
	}

	for _, lock := range locks {
		defer lock.Unlock()
	}

	// At this point it's safe to unlock, unlock is idempotent, so it's safe to call these here
	// we've locked the individual files involved, meaning no one should be able to use those IPs
	// and it's safe the unlock.
	// We unlock here, because in freeIPs, it can take quite a while (minutes).
	lock.Unlock()

	err = mgr.freeIPs(parentCtx, deallocationList)
	if err != nil {
		return err
	}

	// Do file deletions
	return mgr.doFileCleanup(parentCtx, deallocationList)
}

func (mgr *IPPoolManager) doFileCleanup(parentCtx *context.VPCContext, deallocationList []string) error {
	timeout := 0 * time.Second
	recordsNotToDelete := make(map[string]struct{})
	for _, ip := range deallocationList {
		recordsNotToDelete[ip] = struct{}{}
	}

	for _, ip := range mgr.networkInterface.GetIPv4Addresses() {
		recordsNotToDelete[ip] = struct{}{}
	}

	records, err := parentCtx.FSLocker.ListFiles(mgr.ipAddressesPath())
	if err != nil {
		return err
	}
	for _, record := range records {
		logEntry := parentCtx.Logger.WithField("record", record.Name)
		if _, ok := recordsNotToDelete[record.Name]; ok {
			continue
		}
		logEntry.Debug("Checking")
		if time.Since(record.BumpTime) < 5*time.Minute {
			logEntry.WithField("timeSinceBump", time.Since(record.BumpTime)).Debug("Time since bump")
			continue
		}
		logEntry.Info("Removing")
		path := filepath.Join(mgr.ipAddressesPath(), record.Name)
		lock, err := parentCtx.FSLocker.ExclusiveLock(path, &timeout)
		// Seems like this address is in use
		if err == unix.EWOULDBLOCK {
			logEntry.Warning("File currently locked")
			continue
		} else if err != nil {
			logEntry.Error("Unable to lock: ", err)
			continue
		}
		defer lock.Unlock()

		err = parentCtx.FSLocker.RemovePath(path)
		if err != nil {
			logEntry.Error("Unable to remove: ", err)
		}
	}

	return nil
}

func (mgr *IPPoolManager) ipsFreed(ctx *context.VPCContext, oldIPList, deallocationList []string) bool {
	successCount := 0
	for i := 0; i < 180; i++ {
		err := mgr.networkInterface.Refresh(ctx, ctx.AWSSession)
		if err != nil {
			ctx.Logger.Error("Could not refresh IPs: ", err)
		} else {
			allocMap := make(map[string]struct{})
			for _, ip := range mgr.networkInterface.GetIPv4Addresses() {
				allocMap[ip] = struct{}{}
			}

			missingIPs := 0
			for _, oldIP := range oldIPList {
				if _, ok := allocMap[oldIP]; !ok {
					missingIPs++
				}
			}
			if missingIPs > 0 {
				ctx.Logger.Infof("%d IPs successfully freed; intended to free: %d", missingIPs, len(deallocationList))
				successCount++
				if successCount > 3 {
					return true
				}
			} else {
				ctx.Logger.Info("Resetting freed success count to 0")
				// Reset the success count
				successCount = 0
			}
		}
		time.Sleep(mgr.ipRefreshSleepInterval)
	}
	return false
}

func (mgr *IPPoolManager) freeIPs(parentCtx *context.VPCContext, deallocationList []string) error {
	// Prioritize giving IPs back to Amazon
	oldIPList := mgr.networkInterface.GetIPv4Addresses()
	if len(deallocationList) == 0 {
		return nil
	}

	parentCtx.Logger.Info("Deallocating Ip addresses: ", deallocationList)
	if err := mgr.networkInterface.FreeIPv4Addresses(parentCtx, parentCtx.AWSSession, deallocationList); err != nil {
		return err
	}

	if !mgr.ipsFreed(parentCtx, oldIPList, deallocationList) {
		parentCtx.Logger.Warning("IP Refresh failed on GC")
	}

	return nil
}
