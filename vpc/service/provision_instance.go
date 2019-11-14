package service

import (
	"context"
	"database/sql"
	"time"

	"go.opencensus.io/trace"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/pkg/errors"
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

	instance, ownerID, err := ec2InstanceSession.GetInstance(ctx, req.InstanceIdentity.InstanceID, ec2wrapper.InvalidateCache|ec2wrapper.StoreInCache)
	if err != nil {
		return nil, err
	}
	maxInterfaces, err := vpc.GetMaxInterfaces(aws.StringValue(instance.InstanceType))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Check if we need to attach interfaces
	logger.G(ctx).WithField("req", req).Debug()
	if len(instance.NetworkInterfaces) != maxInterfaces {
		// Code to attach interfaces
		if req.AccountID != "" && req.AccountID != ownerID {
			ec2InterfaceSession, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{
				AccountID: req.AccountID,
				Region:    req.InstanceIdentity.Region,
			})
			if err != nil {
				return nil, err
			}
			return vpcService.attachNetworkInterfaces(ctx, ec2InstanceSession, ec2InterfaceSession, instance, maxInterfaces, req.InstanceIdentity.Region, req.InstanceIdentity.AccountID, req.AccountID, req.SubnetID)
		}
		return vpcService.attachNetworkInterfaces(ctx, ec2InstanceSession, ec2InstanceSession, instance, maxInterfaces, req.InstanceIdentity.Region, req.InstanceIdentity.AccountID, req.InstanceIdentity.AccountID, aws.StringValue(instance.SubnetId))
	}

	return &vpcapi.ProvisionInstanceResponse{
		NetworkInterfaces: instanceNetworkInterfaces(*instance, instance.NetworkInterfaces),
	}, nil
}

func (vpcService *vpcService) attachNetworkInterfaces(ctx context.Context, ec2InstanceSession, ec2InterfaceSession *ec2wrapper.EC2Session, instance *ec2.Instance, maxInterfaces int, region, instanceAccountID, requestedAccountID, subnetID string) (*vpcapi.ProvisionInstanceResponse, error) {
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
			networkInterface, err := vpcService.attachNetworkInterfaceAtIdx(ctx, ec2InstanceSession, ec2InterfaceSession, instance, i, region, instanceAccountID, requestedAccountID, subnetID)
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

func (vpcService *vpcService) attachNetworkInterfaceAtIdx(ctx context.Context, ec2InstanceSession, ec2InterfaceSession *ec2wrapper.EC2Session, instance *ec2.Instance, idx int, region, instanceAccountID, requestedAccountID, subnetID string) (*ec2.NetworkInterface, error) {
	ctx = logger.WithLogger(ctx, logger.G(ctx).WithField("idx", idx))
	logger.G(ctx).WithFields(map[string]interface{}{
		"region":             region,
		"instanceAccountID":  instanceAccountID,
		"requestedAccountID": requestedAccountID,
		"subnetID":           subnetID,
	}).Debug("Attaching network interface")

	instanceEC2Client := ec2.New(ec2InstanceSession.Session)
	interfaceEC2Client := ec2.New(ec2InterfaceSession.Session)

	createNetworkInterfaceInput := &ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(vpc.NetworkInterfaceDescription),
		SubnetId:         aws.String(subnetID),
		Ipv6AddressCount: aws.Int64(0),
	}

	createNetworkInterfaceResult, err := interfaceEC2Client.CreateNetworkInterfaceWithContext(ctx, createNetworkInterfaceInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not create interface")
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
	_, err = interfaceEC2Client.CreateTagsWithContext(ctx, createTagsInput)
	if err != nil {
		logger.G(ctx).WithError(err).Warn("Could not tag network interface")
	}

	if requestedAccountID != instanceAccountID {
		createNetworkInterfacePermissionInput := &ec2.CreateNetworkInterfacePermissionInput{
			AwsAccountId:       aws.String(instanceAccountID),
			NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
			Permission:         aws.String("INSTANCE-ATTACH"),
		}
		_, err = interfaceEC2Client.CreateNetworkInterfacePermission(createNetworkInterfacePermissionInput)
		if err != nil {
			return nil, errors.Wrap(err, "Could not create network interface permission")
		}
	}

	attachNetworkInterfaceInput := &ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        aws.Int64(int64(idx)),
		InstanceId:         instance.InstanceId,
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}

	// TODO: Delete interface if attaching fails.
	// TODO: Add retries to attach the interface
	attachNetworkInterfaceResult, err := instanceEC2Client.AttachNetworkInterfaceWithContext(ctx, attachNetworkInterfaceInput)
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
	_, err = interfaceEC2Client.ModifyNetworkInterfaceAttributeWithContext(ctx, modifyNetworkInterfaceAttributeInput)
	// This isn't actually the end of the world as long as someone comes and fixes it later
	if err != nil {
		logger.G(ctx).WithError(err).Warn("Could not reconfigure network interface to be deleted on termination")
	}

	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: aws.StringSlice([]string{*createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId}),
	}

	// TODO: Retry
	// TODO: Consistency check.
	describeNetworkInterfacesOutput, err := interfaceEC2Client.DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not fetch interface after configuration")
		return nil, status.Convert(err).Err()
	}

	if len(describeNetworkInterfacesOutput.NetworkInterfaces) == 0 {
		return nil, status.Error(codes.NotFound, "Could not find interface")
	}

	logger.G(ctx).WithField("networkInterface", describeNetworkInterfacesOutput.NetworkInterfaces[0]).Debug("Attached network interface")
	return describeNetworkInterfacesOutput.NetworkInterfaces[0], nil
}

func (vpcService *vpcService) ProvisionInstanceV2(ctx context.Context, req *vpcapi.ProvisionInstanceRequestV2) (_ *vpcapi.ProvisionInstanceResponseV2, retErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "ProvisionInstanceV2")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)

	// - Add instance AZ, etc.. to logger
	// TODO:
	// - Check that the AWS instance is in the same account as our session object
	// - Add timeout
	// - Verify instance identity document
	// - Check the server's region is our own
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = status.Error(codes.Unknown, errors.Wrap(err, "Could not start database transaction").Error())
		span.SetStatus(traceStatusFromError(err))
		return nil, err
	}
	defer func() {
		if retErr == nil {
			retErr = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}()

	ec2InstanceSession, err := vpcService.ec2.GetSessionFromInstanceIdentity(ctx, req.InstanceIdentity)
	if err != nil {
		return nil, err
	}

	instance, _, err := ec2InstanceSession.GetInstance(ctx, req.InstanceIdentity.InstanceID, ec2wrapper.InvalidateCache)
	if err != nil {
		return nil, err
	}

	// Does this have 2 network interfaces?
	// TODO: Verify the second network interface is a trunk
	eni := vpcService.getTrunkENI(instance)
	if eni != nil {
		return &vpcapi.ProvisionInstanceResponseV2{
			TrunkNetworkInterface: instanceNetworkInterface(*instance, *eni),
		}, nil
	}

	createNetworkInterfaceInput := &ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(vpc.TrunkNetworkInterfaceDescription),
		InterfaceType:    aws.String("trunk"),
		Ipv6AddressCount: aws.Int64(0),
		SubnetId:         instance.SubnetId,
	}

	ec2client := ec2.New(ec2InstanceSession.Session)

	// TODO: Record creation of the interface
	createNetworkInterfaceResult, err := ec2client.CreateNetworkInterfaceWithContext(ctx, createNetworkInterfaceInput)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not create interface")
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
		DeviceIndex:        aws.Int64(int64(1)),
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

	// TODO: Add retries to modify the interface
	modifyNetworkInterfaceAttributeInput = &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment: &ec2.NetworkInterfaceAttachmentChanges{
			AttachmentId: attachNetworkInterfaceResult.AttachmentId,
		},
		SourceDestCheck:    &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}
	_, err = ec2client.ModifyNetworkInterfaceAttributeWithContext(ctx, modifyNetworkInterfaceAttributeInput)
	// This isn't actually the end of the world as long as someone comes and fixes it later
	if err != nil {
		logger.G(ctx).WithError(err).Warn("Could not reconfigure network interface to disable source / dest check")
	}

	return &vpcapi.ProvisionInstanceResponseV2{}, nil
}
