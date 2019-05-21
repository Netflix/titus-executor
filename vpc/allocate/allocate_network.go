package allocate

import (
	"context"
	"encoding/json"
	"fmt"
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

var (
	errInterfaceNotFoundAtIndex   = errors.New("Network interface not found at index")
	errSecurityGroupsNotConverged = errors.New("Security groups for interface not converged")
)

func AllocateNetwork(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn, securityGroups []string, deviceIdx int, allocateIPv6Address bool) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"deviceIdx":           deviceIdx,
		"security-groups":     securityGroups,
		"allocateIPv6Address": allocateIPv6Address,
	})
	logger.G(ctx).Debug()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address)
	conn.Close()
	if err != nil {
		err := errors.Wrap(err, "Unable to perform network allocation")
		err = json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if err != nil {
			err = errors.Wrap(err, err.Error())
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

func (a *allocation) addAllocation(addr *vpcapi.UsableAddress, lock *fslocker.ExclusiveLock) {
	if addr.Address.Family == titus.Family_FAMILY_V4 {
		if a.ip4Address != nil {
			panic("Trying to add two IPv4 allocation to alloc object")
		}
		a.ip4Address = addr
		if a.exclusiveIP4Lock != nil {
			panic("trying to add two IPv4 locks to alloc object")
		}
		a.exclusiveIP4Lock = lock
	} else if addr.Address.Family == titus.Family_FAMILY_V6 {
		if a.ip6Address != nil {
			panic("Trying to add two IPv6 allocation to alloc object")
		}
		a.ip6Address = addr
		if a.exclusiveIP6Lock != nil {
			panic("trying to add two IPv6 locks to alloc object")
		}
		a.exclusiveIP6Lock = lock
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
	instanceIdentity, err := instanceIdentityProvider.GetIdentity()
	if err != nil {
		return nil, errors.Wrap(err, "Cannot retrieve instance identity")
	}

	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 10 * time.Second

	configurationLockPath := utilities.GetConfigurationLockPath(deviceIdx)
	addressesLockPath := utilities.GetAddressesLockPath(deviceIdx)

	lock, err := locker.ExclusiveLock(configurationLockPath, &reconfigurationTimeout)
	defer lock.Unlock()
	if err != nil {
		return nil, err
	}
	records, err := locker.ListFiles(addressesLockPath)
	if err != nil {
		return nil, err
	}

	requestedAddresses := []*titus.Address{
		{
			Family: titus.Family_FAMILY_V4,
		},
	}

	if allocateIPv6Address {
		requestedAddresses = append(requestedAddresses, &titus.Address{
			Family: titus.Family_FAMILY_V6,
		})
	}

	utilizedAddresses := make([]*vpcapi.UtilizedAddress, 0, len(records))
	for _, record := range records {
		tmpLock, err := locker.ExclusiveLock(filepath.Join(addressesLockPath, record.Name), &optimisticLockTimeout)
		if err == nil {
			tmpLock.Unlock()
		} else {
			ip := net.ParseIP(record.Name)
			family := titus.Family_FAMILY_V4
			if ip.To4() == nil {
				family = titus.Family_FAMILY_V6
			}

			address := &vpcapi.UtilizedAddress{
				Address: &titus.Address{
					Address: ip.String(),
					Family:  family,
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
		RequestedAddresses:       requestedAddresses,
		UtilizedAddresses:        utilizedAddresses,
		InstanceIdentity:         instanceIdentity,
		AllowSecurityGroupChange: allowSecurityGroupChange,
	}

	logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Debug("Making assign IP request")
	response, err := client.AssignIP(ctx, assignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("AssignIP request failed")
		return nil, errors.Wrap(err, "Error received from VPC Assign Private IP Server")
	}

	logger.G(ctx).WithField("assignIPResponse", response).Info("AssignIP request suceeded")

	if allocateIPv6Address {
		if len(response.GetUsableAddresses()) != 2 {
			return nil, fmt.Errorf("Received %d IP addresses, when expected to receive 2", len(response.GetUsableAddresses()))
		}
	} else {
		if len(response.GetUsableAddresses()) != 1 {
			return nil, fmt.Errorf("Received %d IP addresses, when expected to receive 1", len(response.GetUsableAddresses()))
		}
	}

	alloc := &allocation{}
	alloc.networkInterface = response.NetworkInterface
	for idx := range response.UsableAddresses {
		addr := response.UsableAddresses[idx]
		ip := net.ParseIP(addr.Address.Address)
		exclusiveLock0, err := locker.ExclusiveLock(filepath.Join(addressesLockPath, ip.String()), &optimisticLockTimeout)
		if err != nil {
			alloc.deallocate(ctx)
			return nil, err
		}
		alloc.addAllocation(addr, exclusiveLock0)
	}

	logger.G(ctx).WithField("alloc", alloc.String()).Debug()

	return alloc, nil
}
