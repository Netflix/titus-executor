package gc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/identity"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

func GC(ctx context.Context, timeout time.Duration, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	optimisticTimeout := time.Duration(0)
	exclusiveLock, err := locker.ExclusiveLock(utilities.GetGlobalConfigurationLock(), &optimisticTimeout)
	if err != nil {
		return errors.Wrap(err, "Cannot get global configuration lock")
	}
	defer exclusiveLock.Unlock()

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return errors.Wrap(err, "Unable to get instance identity")
	}

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	maxInterfaces, err := vpc.GetMaxInterfaces(instanceIdentity.InstanceType)
	if err != nil {
		return err
	}
	for i := 1; i < maxInterfaces; i++ {
		err = doGcInterface(ctx, i, locker, client, instanceIdentity)
		if err != nil {
			return err
		}
	}

	return nil
}

func doGcInterface(ctx context.Context, deviceIdx int, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, instanceIdentity *vpcapi.InstanceIdentity) error {
	ctx = logger.WithField(ctx, "deviceIdx", deviceIdx)
	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 10 * time.Second

	configurationLockPath := utilities.GetConfigurationLockPath(deviceIdx)
	addressesLockPath := utilities.GetAddressesLockPath(deviceIdx)

	configurationLock, err := locker.ExclusiveLock(configurationLockPath, &reconfigurationTimeout)
	if err != nil {
		return errors.Wrap(err, "Cannot get exclusive configuration lock on interface")
	}
	logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Took lock on interface configuration lock path")
	defer func() {
		configurationLock.Unlock()
		logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Unlocked configuration lock path")
	}()

	records, err := locker.ListFiles(addressesLockPath)
	if err != nil {
		return err
	}

	unallocatedAddresses := make(map[string]*fslocker.Record, len(records))
	nonviableAddresses := make(map[string]*fslocker.Record, len(records))
	allocatedAddresses := make(map[string]*fslocker.Record, len(records))
	for idx := range records {
		record := records[idx]
		entry := logger.G(ctx).WithField("ip", record.Name)
		entry.Debug("Checking IP")

		addressLockPath := filepath.Join(addressesLockPath, record.Name)
		ipAddrLock, err := locker.ExclusiveLock(addressLockPath, &optimisticLockTimeout)
		if err == unix.EWOULDBLOCK {
			entry.Info("Skipping address, in-use")
			allocatedAddresses[record.Name] = &record
			continue
		} else if err != nil {
			entry.WithError(err).Error("Encountered unknown errror")
			return err
		}
		logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Took exclusive lock on address")
		defer func() {
			ipAddrLock.Unlock()
			logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Released lock on address")
		}()
		unallocatedAddresses[record.Name] = &record
	}

	// At this point it's safe to unlock, unlock is idempotent, so it's safe to call these here
	// we've locked the individual files involved, meaning no one should be able to use those IPs
	// and it's safe the unlock.
	// We unlock here, because in freeIPs, it can take quite a while (minutes).
	configurationLock.Unlock()
	logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Unlocked configuration lock path")

	gcRequest := &vpcapi.GCRequest{
		NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{
			DeviceIndex: uint32(deviceIdx),
		},
		InstanceIdentity:     instanceIdentity,
		AllocatedAddresses:   recordsToUtilizedAddresses(allocatedAddresses),
		NonviableAddresses:   recordsToUtilizedAddresses(nonviableAddresses),
		UnallocatedAddresses: recordsToUtilizedAddresses(unallocatedAddresses),
	}

	gcResponse, err := client.GC(ctx, gcRequest)
	if err != nil {
		return errors.Wrap(err, "Error from IP Service")
	}

	logger.G(ctx).WithField("addresesToDelete", gcResponse.AddressToDelete).Info("Received addresses to delete")
	logger.G(ctx).WithField("addresesToBump", gcResponse.AddressToBump).Info("Received addresses to bump")

	var returnError *multierror.Error
	for _, addr := range gcResponse.AddressToDelete {
		err = locker.RemovePath(filepath.Join(addressesLockPath, addr.Address))
		if err != nil && !os.IsNotExist(err) {
			logger.G(ctx).WithError(err).WithField("address", addr.Address).Error("Could not remove record")
			returnError = multierror.Append(returnError, errors.Wrapf(err, "Cannot remove record %s", addr.Address))
		}
	}

	for _, addr := range gcResponse.AddressToBump {
		tmpLock, err := locker.SharedLock(filepath.Join(addressesLockPath, addr.Address), &optimisticLockTimeout)
		if err == nil {
			tmpLock.Bump()
			tmpLock.Unlock()
		} else if err != unix.EWOULDBLOCK {
			logger.G(ctx).WithError(err).WithField("address", addr.Address).Errorf("Could not bump lock for record")
		}
	}

	return returnError.ErrorOrNil()
}

func recordsToUtilizedAddresses(records map[string]*fslocker.Record) []*vpcapi.UtilizedAddress {
	ret := make([]*vpcapi.UtilizedAddress, 0, len(records))
	for _, record := range records {
		ret = append(ret, &vpcapi.UtilizedAddress{
			Address: &titus.Address{
				Address: net.ParseIP(record.Name).String(),
			},
			LastUsedTime: &timestamp.Timestamp{
				Seconds: int64(record.BumpTime.Second()),
				Nanos:   int32(record.BumpTime.Nanosecond()),
			},
		})
	}
	return ret
}
