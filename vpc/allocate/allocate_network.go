package allocate

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"google.golang.org/grpc"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/identity"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func Allocate(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn, securityGroups []string, deviceIdx int, allocateIPv6Address bool) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"deviceIdx":           deviceIdx,
		"security-groups":     securityGroups,
		"allocateIPv6Address": allocateIPv6Address,
	})
	logger.G(ctx).Info()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address)
	conn.Close()
	if err != nil {
		err = errors.Wrap(err, "Unable to perform network allocation")
		writeError := json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if writeError != nil {
			err = errors.Wrap(writeError, err.Error())
		}
		return err
	}
	ctx = logger.WithField(ctx, "ip4", allocation.ip4Address)
	if allocateIPv6Address {
		ctx = logger.WithField(ctx, "ip6", allocation.ip6Address)
	}
	logger.G(ctx).Info("Network setup")
	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).
		Encode(
			types.Allocation{
				IPV4Address: allocation.ip4Address,
				IPV6Address: allocation.ip6Address,
				DeviceIndex: deviceIdx,
				Success:     true,
				ENI:         allocation.networkInterface.NetworkInterfaceId,
				VPC:         allocation.networkInterface.VpcId,
				MAC:         allocation.networkInterface.MacAddress,
			})
	if err != nil {
		return errors.Wrap(err, "Unable to write allocation record")
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
				logger.G(ctx).Error("Unable to refresh IP allocation record: ", err)
			}
		}
	}
exit:
	logger.G(ctx).Info("Beginning shutdown, and deallocation: ", allocation)

	allocation.deallocate(ctx)
	// TODO: Teardown turned up network namespace
	logger.G(ctx).Info("Finished shutting down and deallocating")
	return nil
}

type allocation struct {
	sharedSGLock     *fslocker.SharedLock
	exclusiveIP4Lock *fslocker.ExclusiveLock
	exclusiveIP6Lock *fslocker.ExclusiveLock
	ip4Address       *vpcapi.UsableAddress
	ip6Address       *vpcapi.UsableAddress
	networkInterface *vpcapi.NetworkInterface
}

func (a *allocation) refresh() error {
	a.exclusiveIP4Lock.Bump()
	if a.exclusiveIP6Lock != nil {
		a.exclusiveIP6Lock.Bump()
	}
	return nil
}

func (a *allocation) deallocate(ctx context.Context) {
	if a.exclusiveIP4Lock != nil {
		a.exclusiveIP4Lock.Unlock()
	}
	if a.exclusiveIP6Lock != nil {
		a.exclusiveIP6Lock.Unlock()
	}
}

func (a *allocation) String() string {
	return fmt.Sprintf("%#v", *a)
}

func doAllocateNetwork(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, securityGroups []string, deviceIdx int, allocateIPv6Address bool) (*allocation, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 10 * time.Second

	securityGroupLockPath := utilities.GetSecurityGroupLockPath(deviceIdx)
	exclusiveSGLock, lockErr := locker.ExclusiveLock(securityGroupLockPath, &optimisticLockTimeout)

	if lockErr == nil {
		alloc, err := doAllocateNetworkAddress(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address, true)
		if err != nil {
			exclusiveSGLock.Unlock()
			return alloc, errors.Wrap(err, "Cannot get shared SG lock")
		}
		alloc.sharedSGLock = exclusiveSGLock.ToSharedLock()
		return alloc, err
	}

	// We cannot get an exclusive lock, maybe we can get a shared lock?
	if lockErr == unix.EWOULDBLOCK {
		sharedSGLock, err := locker.SharedLock(securityGroupLockPath, &reconfigurationTimeout)
		if err != nil {
			return nil, err
		}
		alloc, err := doAllocateNetworkAddress(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address, false)
		if err != nil {
			sharedSGLock.Unlock()
			return alloc, err
		}
		alloc.sharedSGLock = sharedSGLock
		return alloc, err
	}

	return nil, errors.Wrap(lockErr, "Cannot get exclusive SG Lock")
}

func doAllocateNetworkAddress(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, securityGroups []string, deviceIdx int, allocateIPv6Address, allowSecurityGroupChange bool) (*allocation, error) {
	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot retrieve instance identity")
	}

	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 10 * time.Second

	configurationLockPath := utilities.GetConfigurationLockPath(deviceIdx)
	addressesLockPath := utilities.GetAddressesLockPath(deviceIdx)

	lock, err := locker.ExclusiveLock(configurationLockPath, &reconfigurationTimeout)
	if err != nil {
		return nil, err
	}
	logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Took lock on interface configuration lock path")
	defer func() {
		lock.Unlock()
		logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Unlocked configuration lock path")
	}()

	records, err := locker.ListFiles(addressesLockPath)
	if err != nil {
		return nil, err
	}

	utilizedAddresses := make([]*vpcapi.UtilizedAddress, 0, len(records))
	for _, record := range records {
		tmpLock, err := locker.ExclusiveLock(filepath.Join(addressesLockPath, record.Name), &optimisticLockTimeout)
		if err == nil {
			tmpLock.Unlock()
		} else {
			ip := net.ParseIP(record.Name)

			address := &vpcapi.UtilizedAddress{
				Address: &titus.Address{
					Address: ip.String(),
				},
				LastUsedTime: &timestamp.Timestamp{
					Seconds: record.BumpTime.Unix(),
					Nanos:   int32(record.BumpTime.Nanosecond()),
				},
			}
			utilizedAddresses = append(utilizedAddresses, address)
		}
	}

	assignIPRequest := &vpcapi.AssignIPRequest{
		NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{
			DeviceIndex: uint32(deviceIdx),
		},
		SecurityGroupIds:         securityGroups,
		UtilizedAddresses:        utilizedAddresses,
		InstanceIdentity:         instanceIdentity,
		AllowSecurityGroupChange: allowSecurityGroupChange,
		Ipv6AddressRequested:     allocateIPv6Address,
	}

	logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Debug("Making assign IP request")
	response, err := client.AssignIP(ctx, assignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("AssignIP request failed")
		return nil, errors.Wrap(err, "Error received from VPC Assign Private IP Server")
	}

	logger.G(ctx).WithField("assignIPResponse", response).Info("AssignIP request suceeded")

	alloc := &allocation{}
	alloc.networkInterface = response.NetworkInterface
	err = populateAlloc(ctx, alloc, allocateIPv6Address, response.UsableAddresses, locker, addressesLockPath)
	if err != nil {
		return nil, err
	}
	return alloc, nil
}

func populateAlloc(ctx context.Context, alloc *allocation, allocateIPv6Address bool, usableAddresses []*vpcapi.UsableAddress, locker *fslocker.FSLocker, addressesLockPath string) error {
	optimisticLockTimeout := time.Duration(0)

	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(usableAddresses), func(i, j int) { usableAddresses[i], usableAddresses[j] = usableAddresses[j], usableAddresses[i] })
	for idx := range usableAddresses {
		addr := usableAddresses[idx]
		ip := net.ParseIP(addr.Address.Address)
		if ip.To4() == nil {
			continue
		}
		addressLockPath := filepath.Join(addressesLockPath, ip.String())
		lock, err := locker.ExclusiveLock(addressLockPath, &optimisticLockTimeout)
		if err == nil {
			logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Successfully took lock on address")
			alloc.exclusiveIP4Lock = lock
			alloc.ip4Address = addr
			break
		} else if err != unix.EWOULDBLOCK {
			return err
		}
	}

	if alloc.ip4Address == nil {
		return errors.New("Cannot allocate IPv4 address")
	}

	if !allocateIPv6Address {
		return nil
	}

	for idx := range usableAddresses {
		addr := usableAddresses[idx]
		ip := net.ParseIP(addr.Address.Address)
		if ip.To4() != nil {
			continue
		}
		addressLockPath := filepath.Join(addressesLockPath, ip.String())

		lock, err := locker.ExclusiveLock(addressLockPath, &optimisticLockTimeout)
		if err == nil {
			logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Successfully took lock on address")
			alloc.ip6Address = addr
			alloc.exclusiveIP6Lock = lock
			break
		} else if err != unix.EWOULDBLOCK {
			alloc.exclusiveIP4Lock.Unlock()
			return err
		}
	}

	if alloc.ip6Address == nil {
		alloc.exclusiveIP4Lock.Unlock()
		return errors.New("Cannot allocate IPv6 address")
	}

	return nil
}
