package assign3

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

type Arguments struct {
	SecurityGroups     []string
	SubnetIds          []string
	IPv4AllocationUUID string
	InterfaceAccount   string
	TaskID             string
	ElasticIPPool      string
	ElasticIPs         []string
	Idempotent         bool
	Jumbo              bool
	Bandwidth          uint64
	Burst              bool
	NetworkMode        string
}

func Assign(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, conn *grpc.ClientConn, args Arguments) error {
	ctx = logger.WithFields(ctx, map[string]interface{}{
		"network-mode":    args.NetworkMode,
		"security-groups": args.SecurityGroups,
		"allocationUUID":  args.IPv4AllocationUUID,
		"account":         args.InterfaceAccount,
	})
	logger.G(ctx).Info()

	client := vpcapi.NewTitusAgentVPCServiceClient(conn)
	if args.TaskID == "" {
		args.TaskID = uuid.New().String()
		logger.G(ctx).WithField("taskId", args.TaskID).Info("Setting task ID")
	}

	m := protojson.MarshalOptions{
		Indent: "\t",
	}

	allocation, err := doAllocateNetwork(ctx, instanceIdentityProvider, client, args)
	if err != nil {
		err = errors.Wrap(err, "Unable to perform network allocation")
		data, serializationError := m.Marshal(&vpcapi.VPCToolResult{
			Result: &vpcapi.VPCToolResult_Error{
				Error: &vpcapi.Error{
					Error: err.Error(),
				},
			},
		})

		if serializationError != nil {
			err = errors.Wrap(serializationError, err.Error())
			return err
		}

		_, writeError := os.Stdout.Write(data)
		if writeError != nil {
			err = errors.Wrap(writeError, err.Error())
			return err
		}
	}

	switch a := allocation.Assignment.(type) {
	case *vpcapi.Assignment_AssignIPResponseV3:
		if a.AssignIPResponseV3.Ipv6Address != nil {
			ctx = logger.WithField(ctx, "ip6", a.AssignIPResponseV3.Ipv6Address)
		}
		if a.AssignIPResponseV3.Ipv4Address != nil {
			ctx = logger.WithField(ctx, "ip4", a.AssignIPResponseV3.Ipv4Address)
		}
	}
	logger.G(ctx).Info("Network setup")

	// We do an initial refresh just to "lick" the IPs, in case our allocation lasts a very short period.
	data, err := m.Marshal(&vpcapi.VPCToolResult{
		Result: &vpcapi.VPCToolResult_Assignment{
			Assignment: allocation,
		},
	})
	if err != nil {
		return errors.Wrap(err, "Unable to serialize allocation record")
	}

	_, err = os.Stdout.Write(data)

	if err != nil {
		return errors.Wrap(err, "Unable to write allocation record")
	}

	return nil
}

func doAllocateNetwork(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, client vpcapi.TitusAgentVPCServiceClient, args Arguments) (*vpcapi.Assignment, error) { // nolint:dupl
	// TODO: Make timeout adjustable
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "doAllocateNetwork")
	defer span.End()
	span.AddAttributes(trace.Int64Attribute("pid", int64(os.Getpid())))

	shouldAssignV6 := shouldAssignV6(args)
	shouldAssignV4 := shouldAssignV4(args)

	span.AddAttributes(
		trace.StringAttribute("security-groups", fmt.Sprintf("%v", args.SecurityGroups)),
		trace.BoolAttribute("allocateIPv6Address", shouldAssignV6),
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
		Subnets:          args.SubnetIds,
		InstanceIdentity: instanceIdentity,
		AccountID:        args.InterfaceAccount,
		Idempotent:       args.Idempotent,
		Jumbo:            args.Jumbo,
		Bandwidth:        args.Bandwidth,
		Burst:            args.Burst,
	}

	if shouldAssignV6 {
		assignIPRequest.Ipv6 = &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{
			Ipv6AddressRequested: true,
		}
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
	} else if shouldAssignV4 {
		assignIPRequest.Ipv4 = &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{Ipv4AddressRequested: true}
	} else if args.NetworkMode == titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String() || args.NetworkMode == titus.NetworkConfiguration_HighScale.String() {
		assignIPRequest.Ipv4 = &vpcapi.AssignIPRequestV3_TransitionRequested{}
	} else {
		logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Warning("Experimental: Not assigning IPv4")
	}

	logger.G(ctx).WithField("assignIPRequest", assignIPRequest).Debug("Making assign IP request")
	response, err := client.AssignIPV3(ctx, assignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("AssignIP request failed")
		tracehelpers.SetStatus(err, span)
		return nil, errors.Wrap(err, "Error received from VPC Assign Private IP Server")
	}

	logger.G(ctx).WithField("assignIPResponse", response).Info("AssignIP request suceeded")

	return &vpcapi.Assignment{
		Assignment: &vpcapi.Assignment_AssignIPResponseV3{
			AssignIPResponseV3: response,
		},
	}, nil
}

func shouldAssignV6(args Arguments) bool {
	switch args.NetworkMode {
	case titus.NetworkConfiguration_Ipv6Only.String():
		return true
	case titus.NetworkConfiguration_Ipv6AndIpv4.String():
		return true
	case titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String(), titus.NetworkConfiguration_HighScale.String():
		return true
	default:
		return false
	}
}

func shouldAssignV4(args Arguments) bool {
	// The only case where we don't assign V4 is the V6-only mode.
	return args.NetworkMode != titus.NetworkConfiguration_Ipv6Only.String()
}
