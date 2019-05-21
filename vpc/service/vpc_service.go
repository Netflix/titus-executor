package service

import (
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)
import "context"

type vpcService struct {
	metrics *statsd.Client
	session *session.Session
}

func (*vpcService) GC(context.Context, *vpcapi.GCRequest) (*vpcapi.GCResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Not yet implemented")
}

func (vpcService *vpcService) ProvisionInstance(ctx context.Context, req *vpcapi.ProvisionInstanceRequest) (*vpcapi.ProvisionInstanceResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	// - Add instance AZ, etc.. to logger
	// TODO:
	// - Check that the AWS instance is in the same account as our session object
	// - Add timeout
	// - Verify instance identity document
	// - Check the server's region is our own
	ec2client := ec2.New(vpcService.session)
	describeInstancesOutput, err := ec2client.DescribeInstancesWithContext(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{req.InstanceIdentity.GetInstanceID()}),
	})
	log.WithError(err).Error("Received error from AWS during Describe Instances")
	if err != nil {
		return nil, status.Convert(err).Err()
	}

	if describeInstancesOutput.Reservations == nil || len(describeInstancesOutput.Reservations) == 0 {
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 reservations")
	}
	if describeInstancesOutput.Reservations[0].Instances == nil || len(describeInstancesOutput.Reservations[0].Instances) == 0 {
		return nil, status.Error(codes.NotFound, "Describe Instances returned 0 instances")
	}

	instance := describeInstancesOutput.Reservations[0].Instances[0]
	maxInterfaces := vpc.GetMaxInterfaces(*instance.InstanceType)
	// Check if we need to attach interfaces
	if len(instance.NetworkInterfaces) != maxInterfaces {
		// Code to attach interfaces
		return vpcService.attachNetworkInterfaces(ctx, ec2client, instance)
	}

	return &vpcapi.ProvisionInstanceResponse{
		NetworkInterfaces: instanceNetworkInterfaces(*instance, instance.NetworkInterfaces),
	}, nil
}

func (vpcService *vpcService) attachNetworkInterfaces(ctx context.Context, ec2client *ec2.EC2, instance *ec2.Instance) (*vpcapi.ProvisionInstanceResponse, error) {
	// Since this is serial, we can do this in a simple loop.
	// 1. Create the network interfaces
	// 2. Attach the network interfaces
	networkInterfaceByIdx := map[int]*ec2.InstanceNetworkInterface{}
	for idx := range instance.NetworkInterfaces {
		networkInterface := instance.NetworkInterfaces[idx]
		networkInterfaceByIdx[int(*networkInterface.Attachment.DeviceIndex)] = networkInterface
	}

	createdNetworkInterfaces := []*ec2.NetworkInterface{}

	for i := 0; i < vpc.GetMaxInterfaces(*instance.InstanceType); i++ {
		if _, ok := networkInterfaceByIdx[i]; !ok {
			if networkInterface, err := vpcService.attachNetworkInterfaceAtIdx(ctx, ec2client, instance, i); err != nil {
				return nil, err
			} else {
				createdNetworkInterfaces = append(createdNetworkInterfaces, networkInterface)
			}
		}
	}

	existingNetworkInterfaces := instanceNetworkInterfaces(*instance, instance.NetworkInterfaces)
	newNetworkInterfaces := networkInterfaces(createdNetworkInterfaces)

	return &vpcapi.ProvisionInstanceResponse{
		NetworkInterfaces: append(existingNetworkInterfaces, newNetworkInterfaces...),
	}, nil
}

func (vpcService *vpcService) attachNetworkInterfaceAtIdx(ctx context.Context, ec2client *ec2.EC2, instance *ec2.Instance, idx int) (*ec2.NetworkInterface, error) {
	ctx = logger.WithLogger(ctx, logger.G(ctx).WithField("idx", idx))
	// TODO: Make the subnet ID adjustable
	createNetworkInterfaceInput := &ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(vpc.NetworkInterfaceDescription),
		SubnetId:         instance.SubnetId,
		Ipv6AddressCount: aws.Int64(1),
	}

	createNetworkInterfaceResult, err := ec2client.CreateNetworkInterfaceWithContext(ctx, createNetworkInterfaceInput)
	if err != nil {
		return nil, status.Convert(err).Err()
	}

	// TODO: Add retries to tag the interface
	now := time.Now()
	createTagsInput := &ec2.CreateTagsInput{
		Resources: aws.StringSlice([]string{*createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId}),
		Tags: []*ec2.Tag{
			{
				Key:   aws.String(vpc.ENICreationTimeTag),
				Value: aws.String(now.Format(time.RFC3339)),
			},
		},
	}
	_, err = ec2client.CreateTagsWithContext(ctx, createTagsInput)
	if err != nil {
		logger.G(ctx).WithError(err).Warn("Could not tag network interface")
	}

	attachNetworkInterfaceInput := &ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        aws.Int64(int64(idx)),
		InstanceId:         instance.InstanceId,
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}

	// TODO: Delete interface if attaching fails.
	// TODO: Add retries to attach the interface
	attachNetworkInterfaceResult, err := ec2client.AttachNetworkInterfaceWithContext(ctx, attachNetworkInterfaceInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not attach network interface")
		return nil, status.Convert(err).Err()
	}

	// TODO: Add retries to modify the interface
	modifyNetworkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment: &ec2.NetworkInterfaceAttachmentChanges{
			AttachmentId:        attachNetworkInterfaceResult.AttachmentId,
			DeleteOnTermination: aws.Bool(true),
		},
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}
	_, err = ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, modifyNetworkInterfaceAttributeInput)
	// This isn't actually the end of the world as long as someone comes and fixes it later
	if err != nil {
		logger.G(ctx).WithError(err).Warn("Could not reconfigure network interface to be deleted on termination")
	}

	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: aws.StringSlice([]string{*createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId}),
	}

	// TODO: Retry
	// TODO: Consistency check.
	describeNetworkInterfacesOutput, err := ec2client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not fetch interface after configuration")
		return nil, status.Convert(err).Err()
	}

	if len(describeNetworkInterfacesOutput.NetworkInterfaces) == 0 {
		return nil, status.Error(codes.NotFound, "Could not find interface")
	}

	return describeNetworkInterfacesOutput.NetworkInterfaces[0], nil
}
