package service

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	"go.opencensus.io/trace"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
)

func (vpcService *vpcService) ProvisionInstanceV3(ctx context.Context, req *vpcapi.ProvisionInstanceRequestV3) (*vpcapi.ProvisionInstanceResponseV3, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "ProvisionInstanceV3")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	networkInterface, err := vpcService.provisionInstanceShared(ctx, req.InstanceIdentity, 3)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return &vpcapi.ProvisionInstanceResponseV3{
		TrunkNetworkInterface: networkInterface,
	}, nil
}

func (vpcService *vpcService) provisionInstanceShared(ctx context.Context, instanceIdentity *vpcapi.InstanceIdentity, generation int) (*vpcapi.NetworkInterface, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "provisionInstanceShared")
	defer span.End()

	ec2InstanceSession, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, instanceIdentity)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	instance, _, err := ec2InstanceSession.GetInstance(ctx, instanceIdentity.InstanceID, true)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	// Does this have 2 network interfaces?
	// TODO: Verify the second network interface is a trunk
	eni := vpcService.getTrunkENI(instance)
	if eni != nil {
		return instanceNetworkInterface(*instance, *eni), nil
	}

	iface, err := vpcService.createNewTrunkENI(ctx, ec2InstanceSession, instance.SubnetId, generation)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	attachNetworkInterfaceInput := ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        aws.Int64(int64(1)),
		InstanceId:         instance.InstanceId,
		NetworkInterfaceId: iface.NetworkInterfaceId,
	}

	// TODO: Delete interface if attaching fails.
	_, err = ec2InstanceSession.AttachNetworkInterface(ctx, attachNetworkInterfaceInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not attach network interface")
		return nil, ec2wrapper.HandleEC2Error(err, span)
	}

	return networkInterface(*iface), nil
}
