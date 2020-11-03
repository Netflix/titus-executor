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
	"sort"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"go.opencensus.io/trace"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/Netflix/titus-executor/vpc/utilities"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

func Allocate(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn, securityGroups []string, deviceIdx int, allocateIPv6Address bool, allocationUUID string) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"deviceIdx":           deviceIdx,
		"security-groups":     securityGroups,
		"allocateIPv6Address": allocateIPv6Address,
		"allocationUUID":      allocationUUID,
	})
	logger.G(ctx).Info()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address, allocationUUID)
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
	// We do an initial refresh just to "lick" the IPs, in case our allocation lasts a very short period.
	_ = allocation.refresh()

	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).
		Encode(
			types.LegacyAllocation{
				IPV4Address: allocation.ip4Address,
				IPV6Address: allocation.ip6Address,
				DeviceIndex: deviceIdx,
				Success:     true,
				ENI:         allocation.networkInterface.NetworkInterfaceId,
				VPC:         allocation.networkInterface.VpcId,
				MAC:         allocation.networkInterface.MacAddress,
				Generation:  types.GenerationPointer(types.V1),
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

func doAllocateNetwork(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, securityGroups []string, deviceIdx int, allocateIPv6Address bool, allocationUUID string) (*allocation, error) { // nolint:dupl
	// TODO: Make timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "doAllocateNetwork")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("pid", int64(os.Getpid())))

	span.AddAttributes(
		trace.Int64Attribute("deviceIdx", int64(deviceIdx)),
		trace.StringAttribute("security-groups", fmt.Sprintf("%v", securityGroups)),
		trace.BoolAttribute("allocateIPv6Address", allocateIPv6Address),
	)
	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 10 * time.Second

	securityGroupLockPath := utilities.GetSecurityGroupLockPath(deviceIdx)
	exclusiveSGLock, lockErr := locker.ExclusiveLock(ctx, securityGroupLockPath, &optimisticLockTimeout)

	if lockErr == nil {
		alloc, err := doAllocateNetworkAddress(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address, true, allocationUUID)
		if err != nil {
			exclusiveSGLock.Unlock()
			tracehelpers.SetStatus(err, span)
			return alloc, errors.Wrap(err, "Cannot get shared SG lock")
		}
		alloc.sharedSGLock = exclusiveSGLock.ToSharedLock()
		tracehelpers.SetStatus(err, span)
		return alloc, err
	}

	// We cannot get an exclusive lock, maybe we can get a shared lock?
	if lockErr == unix.EWOULDBLOCK {
		sharedSGLock, err := locker.SharedLock(ctx, securityGroupLockPath, &reconfigurationTimeout)
		if err != nil {
			return nil, err
		}
		alloc, err := doAllocateNetworkAddress(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address, false, allocationUUID)
		if err != nil {
			sharedSGLock.Unlock()
			tracehelpers.SetStatus(err, span)
			return alloc, err
		}
		alloc.sharedSGLock = sharedSGLock
		tracehelpers.SetStatus(err, span)
		return alloc, err
	}

	tracehelpers.SetStatus(lockErr, span)
	return nil, errors.Wrap(lockErr, "Cannot get exclusive SG Lock")
}

func doAllocateNetworkAddress(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, securityGroups []string, deviceIdx int, allocateIPv6Address, allowSecurityGroupChange bool, allocationUUID string) (*allocation, error) {
	ctx, span := trace.StartSpan(ctx, "doAllocateNetworkAddress")
	defer span.End()

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot retrieve instance identity")
	}

	optimisticLockTimeout := time.Duration(0) // nolint:dupl
	reconfigurationTimeout := 10 * time.Second

	configurationLockPath := utilities.GetConfigurationLockPath(deviceIdx)
	addressesLockPath := utilities.GetAddressesLockPath(deviceIdx)

	lock, err := locker.ExclusiveLock(ctx, configurationLockPath, &reconfigurationTimeout)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Took lock on interface configuration lock path")
	defer func() {
		lock.Unlock()
		logger.G(ctx).WithField("configurationLockPath", configurationLockPath).Info("Unlocked configuration lock path")
	}()

	records, err := locker.ListFiles(addressesLockPath)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	previouslyKnownAddresses := set.NewSet()
	utilizedAddresses := make([]*vpcapi.UtilizedAddress, 0, len(records))
	for _, record := range records {
		ip := net.ParseIP(record.Name)
		previouslyKnownAddresses.Add(ip.String())

		tmpLock, err := locker.ExclusiveLock(ctx, filepath.Join(addressesLockPath, record.Name), &optimisticLockTimeout)
		if err == nil {
			tmpLock.Unlock()
		} else {
			address := &vpcapi.UtilizedAddress{
				Address: &vpcapi.Address{
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
	if allocationUUID != "" {
		assignIPRequest.SignedAddressAllocations = []*titus.SignedAddressAllocation{
			{
				AddressAllocation: &titus.AddressAllocation{
					Uuid: allocationUUID,
				},
			},
		}
	}

	logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Debug("Making assign IP request")
	response, err := client.AssignIP(ctx, assignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("AssignIP request failed")
		tracehelpers.SetStatus(err, span)
		return nil, errors.Wrap(err, "Error received from VPC Assign Private IP Server")
	}

	logger.G(ctx).WithField("assignIPResponse", response).Info("AssignIP request suceeded")

	bumpUsableAddresses(ctx, addressesLockPath, previouslyKnownAddresses, response.UsableAddresses, locker)

	alloc := &allocation{}
	alloc.networkInterface = response.NetworkInterface
	err = populateAlloc(ctx, alloc, allocateIPv6Address, response.UsableAddresses, locker, addressesLockPath)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	return alloc, nil
}

func bumpUsableAddresses(ctx context.Context, addressesLockPath string, previouslyKnownAddresses set.Set, usableAddresses []*vpcapi.UsableAddress, locker *fslocker.FSLocker) {
	ctx, span := trace.StartSpan(ctx, "bumpUsableAddresses")
	defer span.End()
	optimisticLockTimeout := time.Duration(0)

	for idx := range usableAddresses {
		addr := usableAddresses[idx]
		ip := net.ParseIP(addr.GetAddress().Address)
		if !previouslyKnownAddresses.Contains(ip.String()) {
			logger.G(ctx).WithField("previouslyKnownAddresses", previouslyKnownAddresses.String()).WithField("ip", ip.String()).Info("Bumping record")
			addressLockPath := filepath.Join(addressesLockPath, ip.String())
			lock, err := locker.ExclusiveLock(ctx, addressLockPath, &optimisticLockTimeout)
			if err == nil {
				lock.Bump()
				lock.Unlock()
			}
		}
	}
}

func populateAlloc(ctx context.Context, alloc *allocation, allocateIPv6Address bool, usableAddresses []*vpcapi.UsableAddress, locker *fslocker.FSLocker, addressesLockPath string) error {
	ctx, span := trace.StartSpan(ctx, "populateAlloc")
	defer span.End()

	optimisticLockTimeout := time.Duration(0)

	r := rand.New(rand.NewSource(time.Now().UnixNano())) // nolint: gosec

	timestamps := map[string]time.Time{}
	records, err := locker.ListFiles(addressesLockPath)
	if err == nil {
		for idx := range records {
			timestamps[net.ParseIP(records[idx].Name).String()] = records[idx].BumpTime
		}
	}
	logger.G(ctx).WithField("timestamps", timestamps).Info()

	sort.Slice(usableAddresses, func(first, second int) bool {
		firstIP := net.ParseIP(usableAddresses[first].Address.Address).String()
		firstTimestamp, ok := timestamps[firstIP]
		if !ok {
			firstTimestamp = time.Unix(r.Int63(), r.Int63())
			timestamps[firstIP] = firstTimestamp
		}
		secondIP := net.ParseIP(usableAddresses[second].Address.Address).String()
		secondTimestamp, ok := timestamps[secondIP]
		if !ok {
			secondTimestamp = time.Unix(r.Int63(), r.Int63())
			timestamps[secondIP] = secondTimestamp
		}

		return firstTimestamp.Before(secondTimestamp)
	})

	logger.G(ctx).WithField("sorted", usableAddresses).Info()

	for idx := range usableAddresses {
		addr := usableAddresses[idx]
		ip := net.ParseIP(addr.Address.Address)
		if ip.To4() == nil {
			continue
		}
		addressLockPath := filepath.Join(addressesLockPath, ip.String())
		lock, err := locker.ExclusiveLock(ctx, addressLockPath, &optimisticLockTimeout)
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

		lock, err := locker.ExclusiveLock(ctx, addressLockPath, &optimisticLockTimeout)
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
