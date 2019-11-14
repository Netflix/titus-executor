package gc2

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
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

	response, err := client.GCSetup(ctx, &vpcapi.GCSetupRequest{
		InstanceIdentity: instanceIdentity,
	})
	if err != nil {
		return err
	}

	var result *multierror.Error
	for _, i := range response.NetworkInterfaceAttachment {
		err = doGcInterface(ctx, i, locker, client, instanceIdentity)
		if err != nil {
			result = multierror.Append(result, err)
		}
	}

	return result.ErrorOrNil()
}

func doGcInterface(ctx context.Context, attachment *vpcapi.NetworkInterfaceAttachment, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, instanceIdentity *vpcapi.InstanceIdentity) error {
	ctx, span := trace.StartSpan(ctx, "doGcInterface")
	defer span.End()
	span.AddAttributes(
		trace.Int64Attribute("deviceIdx", int64(attachment.DeviceIndex)),
		trace.StringAttribute("id", attachment.Id),
	)

	ctx = logger.WithField(ctx, "deviceIdx", attachment.DeviceIndex)
	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 10 * time.Second

	configurationLockPath := utilities.GetConfigurationLockPath(int(attachment.DeviceIndex))
	addressesLockPath := utilities.GetAddressesLockPath(int(attachment.DeviceIndex))

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
		tracehelpers.SetStatus(err, span)
		return err
	}

	allocatedAddresses := sets.NewString()
	unallocatedAddresses := sets.NewString()

	for idx := range records {
		record := records[idx]
		entry := logger.G(ctx).WithField("ip", record.Name)
		entry.Debug("Checking IP")

		addressLockPath := filepath.Join(addressesLockPath, record.Name)
		ipAddrLock, err := locker.ExclusiveLock(addressLockPath, &optimisticLockTimeout)
		if err == unix.EWOULDBLOCK {
			entry.Info("Skipping address, in-use")
			allocatedAddresses.Insert(record.Name)
			continue
		} else if err != nil {
			entry.WithError(err).Error("Encountered unknown errror")
			tracehelpers.SetStatus(err, span)
			return err
		}
		logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Took exclusive lock on address")
		defer func() {
			ipAddrLock.Unlock()
			logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Released lock on address")
		}()
		unallocatedAddresses.Insert(record.Name)
	}
	logger.G(ctx).WithFields(map[string]interface{}{
		"allocatedAddresses":   allocatedAddresses.List(),
		"unallocatedAddresses": unallocatedAddresses.List(),
	}).Info()

	gcRequest := &vpcapi.GCRequestV2{
		InstanceIdentity:           instanceIdentity,
		NetworkInterfaceAttachment: attachment,
		AllocatedAddresses:         setToAddresses(allocatedAddresses),
		UnallocatedAddresses:       setToAddresses(unallocatedAddresses),
	}

	gcResponse, err := client.GCV2(ctx, gcRequest)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return errors.Wrap(err, "Error from IP Service")
	}

	logger.G(ctx).WithField("addresesToDelete", gcResponse.AddressToDelete).Info("Received addresses to delete")

	var returnError *multierror.Error
	for _, addr := range gcResponse.AddressToDelete {
		if ok := unallocatedAddresses.Has(addr.Address); !ok {
			logger.G(ctx).WithField("addr", addr).Warn("Trying to remove address that we don't have an exclusive lock for")
			continue
		}
		err = locker.RemovePath(filepath.Join(addressesLockPath, addr.Address))
		if err != nil && !os.IsNotExist(err) {
			logger.G(ctx).WithError(err).WithField("address", addr.Address).Error("Could not remove record")
			returnError = multierror.Append(returnError, errors.Wrapf(err, "Cannot remove record %s", addr.Address))
		}
	}

	tracehelpers.SetStatus(returnError.ErrorOrNil(), span)
	return returnError.ErrorOrNil()
}

func setToAddresses(records sets.String) []*vpcapi.Address {
	ret := make([]*vpcapi.Address, 0, records.Len())
	for _, record := range records.List() {
		ret = append(ret, &vpcapi.Address{
			Address: record,
		})
	}
	return ret
}
