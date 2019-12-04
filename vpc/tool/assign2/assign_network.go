package assign2

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

const (
	maxAllocationIndex = 10240
)

func Assign(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn, securityGroups []string, deviceIdx int, allocateIPv6Address bool, allocationUUID string) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"deviceIdx":           deviceIdx,
		"security-groups":     securityGroups,
		"allocateIPv6Address": allocateIPv6Address,
		"allocationUUID":      allocationUUID,
	})
	logger.G(ctx).Info()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	indexLock, allocationIndex, err := doAllocateIndex(ctx, locker)
	if err != nil {
		err = errors.Wrap(err, "Unable to perform index allocation")
		writeError := json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if writeError != nil {
			err = errors.Wrap(writeError, err.Error())
		}
		return err
	}
	defer indexLock.Unlock()

	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, locker, client, securityGroups, deviceIdx, allocateIPv6Address, allocationUUID)
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

	nextRefresh := allocation.refresh(ctx, client)
	timer := time.NewTimer(nextRefresh)

	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).
		Encode(
			types.Allocation{
				IPV4Address:     allocation.ip4Address,
				IPV6Address:     allocation.ip6Address,
				DeviceIndex:     deviceIdx,
				Success:         true,
				BranchENIID:     allocation.branchNetworkInterface.NetworkInterfaceId,
				BranchENIMAC:    allocation.branchNetworkInterface.MacAddress,
				BranchENIVPC:    allocation.branchNetworkInterface.VpcId,
				VlanID:          allocation.vlanID,
				TrunkENIID:      allocation.trunkNetworkInterface.NetworkInterfaceId,
				TrunkENIMAC:     allocation.trunkNetworkInterface.MacAddress,
				TrunkENIVPC:     allocation.trunkNetworkInterface.VpcId,
				AllocationIndex: allocationIndex,
			})
	if err != nil {
		return errors.Wrap(err, "Unable to write allocation record")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, unix.SIGTERM, unix.SIGINT)
	defer timer.Stop()
	for {
		select {
		case <-c:
			goto exit
		case <-timer.C:
			nextRefresh = allocation.refresh(ctx, client)
			timer.Reset(nextRefresh)
		}
	}
exit:
	logger.G(ctx).Info("Beginning shutdown, and deallocation: ", allocation)

	allocation.deallocate(ctx)
	// TODO: Teardown turned up network namespace
	logger.G(ctx).Info("Finished shutting down and deallocating")
	return nil
}

func doAllocateIndex(ctx context.Context, locker *fslocker.FSLocker) (*fslocker.ExclusiveLock, uint16, error) {
	optimisticLockTimeout := time.Duration(0)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := r.Intn(maxAllocationIndex); i < maxAllocationIndex; i++ {
		val := (i % (maxAllocationIndex - 3)) + 3
		lock, err := locker.ExclusiveLock(ctx, filepath.Join("allocation-index", strconv.Itoa(val)), &optimisticLockTimeout)
		if err == nil {
			return lock, uint16(val), nil
		}
	}
	return nil, 0, errors.New("Could not generate lock for index")
}

type allocation struct { // nolint:dupl
	sharedSGLock           *fslocker.SharedLock
	exclusiveIP4Lock       *fslocker.ExclusiveLock
	exclusiveIP6Lock       *fslocker.ExclusiveLock
	ip4Address             *vpcapi.UsableAddress
	ip6Address             *vpcapi.UsableAddress
	branchNetworkInterface *vpcapi.NetworkInterface
	trunkNetworkInterface  *vpcapi.NetworkInterface
	vlanID                 int
}

func (a *allocation) refresh(ctx context.Context, client vpcapi.TitusAgentVPCServiceClient) time.Duration {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	now := ptypes.TimestampNow()

	req := &vpcapi.RefreshIPRequest{
		UtilizedAddress: []*vpcapi.UtilizedAddress{},
	}
	if a.exclusiveIP4Lock != nil {
		req.UtilizedAddress = append(req.UtilizedAddress, &vpcapi.UtilizedAddress{
			Address:      a.ip4Address.Address,
			LastUsedTime: now,
		})
	}
	if a.exclusiveIP6Lock != nil {
		req.UtilizedAddress = append(req.UtilizedAddress, &vpcapi.UtilizedAddress{
			Address:      a.ip6Address.Address,
			LastUsedTime: now,
		})
	}

	req.BranchNetworkInterface = a.branchNetworkInterface
	resp, err := client.RefreshIP(ctx, req)
	if err == nil {
		parsedDuration, err := ptypes.Duration(resp.NextRefresh)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Cannot parse next refresh interval from server")
			return vpc.RefreshInterval
		}
		return parsedDuration
	}

	logger.G(ctx).WithError(err).Error("Unable to refresh IP allocation record")
	return vpc.RefreshInterval
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
			return alloc, errors.Wrap(err, "Cannot allocate address under exclusive SG lock")
		}
		alloc.sharedSGLock = exclusiveSGLock.ToSharedLock()
		tracehelpers.SetStatus(err, span)
		return alloc, err
	}

	// We cannot get an exclusive lock, maybe we can get a shared lock?
	if lockErr == unix.EWOULDBLOCK {
		sharedSGLock, err := locker.SharedLock(ctx, securityGroupLockPath, &reconfigurationTimeout)
		if err != nil {
			tracehelpers.SetStatus(err, span)
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

	optimisticLockTimeout := time.Duration(0)
	reconfigurationTimeout := 100 * time.Second

	configurationLockPath := utilities.GetConfigurationLockPath(deviceIdx)
	addressesLockPath := utilities.GetAddressesLockPath(deviceIdx)

	lock, err := locker.ExclusiveLock(ctx, configurationLockPath, &reconfigurationTimeout)
	if err != nil {
		err = errors.Wrap(err, "Unable to get exclusive configuration lock")
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

	utilizedAddresses := make([]*vpcapi.UtilizedAddress, 0, len(records))
	for _, record := range records {
		ip := net.ParseIP(record.Name)

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

	assignIPRequest := &vpcapi.AssignIPRequestV2{
		NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{
			DeviceIndex: uint32(deviceIdx),
		},
		SecurityGroupIds:         securityGroups,
		UtilizedAddresses:        utilizedAddresses,
		InstanceIdentity:         instanceIdentity,
		AllowSecurityGroupChange: allowSecurityGroupChange,
		Ipv6: &vpcapi.AssignIPRequestV2_Ipv6AddressRequested{
			Ipv6AddressRequested: allocateIPv6Address,
		},
	}

	if allocationUUID != "" {
		assignIPRequest.Ipv4 = &vpcapi.AssignIPRequestV2_Ipv4SignedAddressAllocation{
			Ipv4SignedAddressAllocation: &titus.SignedAddressAllocation{
				AddressAllocation: &titus.AddressAllocation{
					Uuid: allocationUUID,
				},
			},
		}
	} else {
		assignIPRequest.Ipv4 = &vpcapi.AssignIPRequestV2_Ipv4AddressRequested{Ipv4AddressRequested: true}
	}

	logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Debug("Making assign IP request")
	response, err := client.AssignIPV2(ctx, assignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("AssignIP request failed")
		tracehelpers.SetStatus(err, span)
		return nil, errors.Wrap(err, "Error received from VPC Assign Private IP Server")
	}

	logger.G(ctx).WithField("assignIPResponse", response).Info("AssignIP request suceeded")

	alloc := &allocation{
		branchNetworkInterface: response.BranchNetworkInterface,
		trunkNetworkInterface:  response.TrunkNetworkInterface,
		vlanID:                 int(response.VlanId),
	}
	err = populateAlloc(ctx, alloc, response, locker, addressesLockPath)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	return alloc, nil
}

func populateAlloc(ctx context.Context, alloc *allocation, response *vpcapi.AssignIPResponseV2, locker *fslocker.FSLocker, addressesLockPath string) (retErr error) {
	ctx, span := trace.StartSpan(ctx, "populateAlloc")
	defer span.End()

	optimisticLockTimeout := time.Duration(0)

	if response.Ipv4Address != nil {
		addressLockPath := filepath.Join(addressesLockPath, response.Ipv4Address.Address.Address)
		lock, err := locker.ExclusiveLock(ctx, addressLockPath, &optimisticLockTimeout)
		if err == nil {
			logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Successfully took lock on address")
			alloc.exclusiveIP4Lock = lock
			lock.Bump()
			alloc.ip4Address = response.Ipv4Address
			defer func() {
				if retErr != nil {
					lock.Unlock()
				}
			}()
		} else if err != unix.EWOULDBLOCK {
			return err
		}
	}

	if response.Ipv6Address != nil {
		addressLockPath := filepath.Join(addressesLockPath, response.Ipv6Address.Address.Address)
		lock, err := locker.ExclusiveLock(ctx, addressLockPath, &optimisticLockTimeout)
		if err == nil {
			logger.G(ctx).WithField("addressLockPath", addressLockPath).Info("Successfully took lock on address")
			alloc.exclusiveIP6Lock = lock
			lock.Bump()
			alloc.ip6Address = response.Ipv6Address
		} else if err != unix.EWOULDBLOCK {
			return err
		}
	}

	return nil
}
