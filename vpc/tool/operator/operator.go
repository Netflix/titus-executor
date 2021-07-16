package operator

import (
	"context"
	"os"

	"google.golang.org/protobuf/encoding/protojson"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
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

	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		Indent:          "\t",
	}
	data, err := marshaler.Marshal(ret)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)
	return err
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

	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		Indent:          "\t",
	}
	data, err := marshaler.Marshal(ret)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)
	return err
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

	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		Indent:          "\t",
	}
	data, err := marshaler.Marshal(ret)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)
	return err
}

func Detach(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, conn *grpc.ClientConn) error {
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	req := vpcapi.DetachBranchNetworkInterfaceRequest{}

	instanceIdentity, err := instanceIdentityProvider.GetIdentity(ctx)
	if err != nil {
		return errors.Wrap(err, "Cannot retrieve instance identity")
	}
	req.TrunkNetworkInterfaceIdentifier = &vpcapi.DetachBranchNetworkInterfaceRequest_InstanceIdentity{
		InstanceIdentity: instanceIdentity,
	}

	ret, err := client.DetachBranchNetworkInterface(ctx, &req)
	if err != nil {
		return errors.Wrap(err, "Failed to describe trunk network interfaces")
	}

	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		Indent:          "\t",
	}
	data, err := marshaler.Marshal(ret)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)
	return err
}
