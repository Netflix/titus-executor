package operator

import (
	"context"
	"os"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

// Operator, I need an exit fast

func Describe(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, conn *grpc.ClientConn, trunkNetworkInterface string) error {
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	req := vpcapi.DescribeTrunkNetworkInterfaceRequest{}

	if trunkNetworkInterface != "" {
		req.TrunkNetworkInterfaceIdentifier = &vpcapi.DescribeTrunkNetworkInterfaceRequest_TrunkENI{
			TrunkENI: trunkNetworkInterface,
		}
	} else {
		instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
		if err != nil {
			return errors.Wrap(err, "Cannot retrieve instance identity")
		}
		req.TrunkNetworkInterfaceIdentifier = &vpcapi.DescribeTrunkNetworkInterfaceRequest_InstanceIdentity{
			InstanceIdentity: instanceIdentity,
		}
	}

	ret, err := client.DescribeTrunkNetworkInterface(ctx, &req)
	if err != nil {
		return errors.Wrap(err, "Failed to describe trunk network interfaces")
	}

	marshaler := jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "\t",
	}
	return marshaler.Marshal(os.Stdout, ret)
}

func Associate(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, conn *grpc.ClientConn, trunkNetworkInterface, branchNetworkInterface string, idx int) error {
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	req := vpcapi.AssociateTrunkNetworkInterfaceRequest{
		BranchENI: branchNetworkInterface,
		VlanId:    uint64(idx),
	}

	if trunkNetworkInterface != "" {
		req.TrunkNetworkInterfaceIdentifier = &vpcapi.AssociateTrunkNetworkInterfaceRequest_TrunkENI{
			TrunkENI: trunkNetworkInterface,
		}
	} else {
		instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
		if err != nil {
			return errors.Wrap(err, "Cannot retrieve instance identity")
		}
		req.TrunkNetworkInterfaceIdentifier = &vpcapi.AssociateTrunkNetworkInterfaceRequest_InstanceIdentity{
			InstanceIdentity: instanceIdentity,
		}
	}

	ret, err := client.AssociateTrunkNetworkInterface(ctx, &req)
	if err != nil {
		return errors.Wrap(err, "Could not associate trunk network interface")
	}

	marshaler := jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "\t",
	}
	return marshaler.Marshal(os.Stdout, ret)
}

func Disassociate(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, conn *grpc.ClientConn, associationID string, force bool) error {
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	req := vpcapi.DisassociateTrunkNetworkInterfaceRequest{
		Force: force,
	}

	req.Key = &vpcapi.DisassociateTrunkNetworkInterfaceRequest_AssociationId{AssociationId: associationID}

	ret, err := client.DisassociateTrunkNetworkInterface(ctx, &req)
	if err != nil {
		return errors.Wrap(err, "Could not disassociate trunk network interface from branch ENI")
	}

	marshaler := jsonpb.Marshaler{
		EmitDefaults: true,
		Indent:       "\t",
	}
	return marshaler.Marshal(os.Stdout, ret)
}
