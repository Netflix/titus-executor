package service

import (
	"context"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
	ec2InstanceSession, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		return nil, err
	}
	instance, err := ec2InstanceSession.GetInstance(ctx)
	if err != nil {
		return nil, err
	}
	maxInterfaces, err := vpc.GetMaxInterfaces(aws.StringValue(instance.InstanceType))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Check if we need to attach interfaces
	if len(instance.NetworkInterfaces) != maxInterfaces {
		// Code to attach interfaces
		return attachNetworkInterfaces(ctx, ec2InstanceSession, instance, maxInterfaces)
	}

	return &vpcapi.ProvisionInstanceResponse{
		NetworkInterfaces: instanceNetworkInterfaces(*instance, instance.NetworkInterfaces),
	}, nil
}

func attachNetworkInterfaces(ctx context.Context, ec2InstanceSession ec2wrapper.EC2InstanceSession, instance *ec2.Instance, maxInterfaces int) (*vpcapi.ProvisionInstanceResponse, error) {
	// Since this is serial, we can do this in a simple loop.
	// 1. Create the network interfaces
	// 2. Attach the network interfaces
	networkInterfaceByIdx := map[int]*ec2.InstanceNetworkInterface{}
	for idx := range instance.NetworkInterfaces {
		networkInterface := instance.NetworkInterfaces[idx]
		networkInterfaceByIdx[int(*networkInterface.Attachment.DeviceIndex)] = networkInterface
	}

	createdNetworkInterfaces := []*ec2.NetworkInterface{}

	for i := 0; i < maxInterfaces; i++ {
		if _, ok := networkInterfaceByIdx[i]; !ok {
			networkInterface, err := attachNetworkInterfaceAtIdx(ctx, ec2InstanceSession, instance, i)
			if err != nil {
				return nil, err
			}
			createdNetworkInterfaces = append(createdNetworkInterfaces, networkInterface)
		}
	}

	existingNetworkInterfaces := instanceNetworkInterfaces(*instance, instance.NetworkInterfaces)
	newNetworkInterfaces := networkInterfaces(createdNetworkInterfaces)

	return &vpcapi.ProvisionInstanceResponse{
		NetworkInterfaces: append(existingNetworkInterfaces, newNetworkInterfaces...),
	}, nil
}

func attachNetworkInterfaceAtIdx(ctx context.Context, ec2InstanceSession ec2wrapper.EC2InstanceSession, instance *ec2.Instance, idx int) (*ec2.NetworkInterface, error) {
	ctx = logger.WithLogger(ctx, logger.G(ctx).WithField("idx", idx))
	// TODO: Make the subnet ID adjustable
	// TODO: Make account is adjustable

	session, err := ec2InstanceSession.Session(ctx)
	if err != nil {
		return nil, err
	}

	ec2client := ec2.New(session)
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
