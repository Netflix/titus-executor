package assign3

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Netflix/titus-executor/vpc/utilities"

	"github.com/pborman/uuid"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

const (
	maxAllocationIndex = 10240
)

type Arguments struct {
	SecurityGroups     []string
	SubnetIds          []string
	AssignIPv6Address  bool
	IPv4AllocationUUID string
	InterfaceAccount   string
	TaskID             string
	Oneshot            bool
}

func Assign(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, conn *grpc.ClientConn, args Arguments) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"security-groups":     args.SecurityGroups,
		"allocateIPv6Address": args.AssignIPv6Address,
		"allocationUUID":      args.IPv4AllocationUUID,
		"account":             args.InterfaceAccount,
	})
	logger.G(ctx).Info()

	optimisticLockTimeout := time.Duration(0)

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

	if args.TaskID == "" {
		args.TaskID = uuid.New()
		logger.G(ctx).WithField("taskId", args.TaskID).Info("Setting task ID")
	}
	lock, err := locker.ExclusiveLock(ctx, filepath.Join(utilities.GetTasksLockPath(), args.TaskID), &optimisticLockTimeout)
	if err != nil {
		return errors.Wrap(err, "Cannot lock assignv3 task lock file")
	}

	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, locker, client, args)
	if err != nil {
		err = errors.Wrap(err, "Unable to perform network allocation")
		writeError := json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if writeError != nil {
			err = errors.Wrap(writeError, err.Error())
		}
		return err
	}
	allocation.taskLock = lock
	ctx = logger.WithField(ctx, "ip4", allocation.ip4Address)
	if args.AssignIPv6Address {
		ctx = logger.WithField(ctx, "ip6", allocation.ip6Address)
	}
	logger.G(ctx).Info("Network setup")
	// We do an initial refresh just to "lick" the IPs, in case our allocation lasts a very short period.

	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).
		Encode(
			types.Allocation{
				IPV4Address:     allocation.ip4Address,
				IPV6Address:     allocation.ip6Address,
				Success:         true,
				BranchENIID:     allocation.branchNetworkInterface.NetworkInterfaceId,
				BranchENIMAC:    allocation.branchNetworkInterface.MacAddress,
				BranchENIVPC:    allocation.branchNetworkInterface.VpcId,
				BranchENISubnet: allocation.branchNetworkInterface.SubnetId,
				VlanID:          allocation.vlanID,
				TrunkENIID:      allocation.trunkNetworkInterface.NetworkInterfaceId,
				TrunkENIMAC:     allocation.trunkNetworkInterface.MacAddress,
				TrunkENIVPC:     allocation.trunkNetworkInterface.VpcId,
				AllocationIndex: allocationIndex,
			})
	if err != nil {
		return errors.Wrap(err, "Unable to write allocation record")
	}

	if args.Oneshot {
		return nil
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, unix.SIGTERM, unix.SIGINT)
	<-c
	logger.G(ctx).Info("Beginning shutdown, and deallocation: ", allocation)

	allocation.deallocate(ctx, client)
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
	ip4Address             *vpcapi.UsableAddress
	ip6Address             *vpcapi.UsableAddress
	branchNetworkInterface *vpcapi.NetworkInterface
	trunkNetworkInterface  *vpcapi.NetworkInterface
	vlanID                 int
	taskID                 string
	taskLock               *fslocker.ExclusiveLock
}

func (a *allocation) deallocate(ctx context.Context, client vpcapi.TitusAgentVPCServiceClient) {
	_, err := client.UnassignIPV3(ctx, &vpcapi.UnassignIPRequestV3{
		TaskId: a.taskID,
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not deallocate allocation")
	}
	a.taskLock.Unlock()
}

func (a *allocation) String() string {
	return fmt.Sprintf("%#v", *a)
}

func doAllocateNetwork(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, locker *fslocker.FSLocker, client vpcapi.TitusAgentVPCServiceClient, args Arguments) (*allocation, error) { // nolint:dupl
	// TODO: Make timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "doAllocateNetwork")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("pid", int64(os.Getpid())))

	span.AddAttributes(
		trace.StringAttribute("security-groups", fmt.Sprintf("%v", args.SecurityGroups)),
		trace.BoolAttribute("allocateIPv6Address", args.AssignIPv6Address),
		trace.StringAttribute("account", args.InterfaceAccount),
		trace.StringAttribute("subnet-ids", fmt.Sprintf("%v", args.SubnetIds)),
	)

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot retrieve instance identity")
	}

	assignIPRequest := &vpcapi.AssignIPRequestV3{
		TaskId:           args.TaskID,
		SecurityGroupIds: args.SecurityGroups,
		Ipv6: &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{
			Ipv6AddressRequested: args.AssignIPv6Address,
		},
		Subnets:          args.SubnetIds,
		InstanceIdentity: instanceIdentity,
		AccountID:        args.InterfaceAccount,
	}

	if args.IPv4AllocationUUID != "" {
		assignIPRequest.Ipv4 = &vpcapi.AssignIPRequestV3_Ipv4SignedAddressAllocation{
			Ipv4SignedAddressAllocation: &titus.SignedAddressAllocation{
				AddressAllocation: &titus.AddressAllocation{
					Uuid: args.IPv4AllocationUUID,
				},
			},
		}
	} else {
		assignIPRequest.Ipv4 = &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{Ipv4AddressRequested: true}
	}

	logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Debug("Making assign IP request")
	response, err := client.AssignIPV3(ctx, assignIPRequest)
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
		taskID:                 args.TaskID,
	}
	err = populateAlloc(ctx, alloc, response)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	return alloc, nil
}

func populateAlloc(ctx context.Context, alloc *allocation, response *vpcapi.AssignIPResponseV3) (retErr error) {
	ctx, span := trace.StartSpan(ctx, "populateAlloc")
	defer span.End()
	_ = ctx

	if response.Ipv4Address != nil {
		alloc.ip4Address = response.Ipv4Address
	}

	if response.Ipv6Address != nil {
		alloc.ip6Address = response.Ipv6Address
	}

	return nil
}
