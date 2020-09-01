package assign3

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/Netflix/titus-executor/vpc/types"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
)

type Arguments struct {
	SecurityGroups     []string
	SubnetIds          []string
	AssignIPv6Address  bool
	IPv4AllocationUUID string
	InterfaceAccount   string
	TaskID             string
	ElasticIPPool      string
	ElasticIPs         []string
	Idempotent         bool
}

func Assign(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, conn *grpc.ClientConn, args Arguments) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"security-groups":     args.SecurityGroups,
		"allocateIPv6Address": args.AssignIPv6Address,
		"allocationUUID":      args.IPv4AllocationUUID,
		"account":             args.InterfaceAccount,
	})
	logger.G(ctx).Info()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	if args.TaskID == "" {
		args.TaskID = uuid.New().String()
		logger.G(ctx).WithField("taskId", args.TaskID).Info("Setting task ID")
	}

	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, client, args)
	if err != nil {
		err = errors.Wrap(err, "Unable to perform network allocation")
		writeError := json.NewEncoder(os.Stdout).Encode(types.Allocation{Success: false, Error: err.Error()})
		if writeError != nil {
			err = errors.Wrap(writeError, err.Error())
		}
		return err
	}
	ctx = logger.WithField(ctx, "ip4", allocation.IPV4Address)
	if args.AssignIPv6Address {
		ctx = logger.WithField(ctx, "ip6", allocation.IPV6Address)
	}
	logger.G(ctx).Info("Network setup")
	// We do an initial refresh just to "lick" the IPs, in case our allocation lasts a very short period.

	// TODO: Output JSON as to new network settings
	err = json.NewEncoder(os.Stdout).Encode(*allocation)
	if err != nil {
		return errors.Wrap(err, "Unable to write allocation record")
	}

	return nil
}

func doAllocateNetwork(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, client vpcapi.TitusAgentVPCServiceClient, args Arguments) (*types.Allocation, error) { // nolint:dupl
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

	if args.ElasticIPPool != "" && len(args.ElasticIPs) > 0 {
		err := fmt.Errorf("Both Elastic IP pool specified (%s), and Elastic IP list (%s) specified", args.ElasticIPPool, args.ElasticIPs)
		span.SetStatus(trace.Status{
			Code:    trace.StatusCodeInvalidArgument,
			Message: err.Error(),
		})
		return nil, err
	}

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
		Idempotent:       args.Idempotent,
	}

	if args.ElasticIPPool != "" {
		assignIPRequest.ElasticAddress = &vpcapi.AssignIPRequestV3_GroupName{
			GroupName: args.ElasticIPPool,
		}
	} else if len(args.ElasticIPs) > 0 {
		assignIPRequest.ElasticAddress = &vpcapi.AssignIPRequestV3_ElasticAdddresses{
			ElasticAdddresses: &vpcapi.ElasticAddressSet{
				ElasticAddresses: args.ElasticIPs,
			},
		}
	} else {
		assignIPRequest.ElasticAddress = &vpcapi.AssignIPRequestV3_Empty{
			Empty: &empty.Empty{},
		}
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

	alloc := types.AssignmentToAllocation(response)
	return &alloc, nil
}
