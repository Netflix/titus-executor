package setup

import (
	"errors"
	"time"

	"net"

	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"gopkg.in/urfave/cli.v1"
)

const (
	maxSetupTime = 2 * time.Minute
)

var Setup = cli.Command{ // nolint: golint
	Name:   "setup",
	Usage:  "Setup",
	Action: context.WrapFunc(setup),
}

func setup(parentCtx *context.VPCContext) error {
	lockTimeout := time.Second
	exclusiveLock, err := parentCtx.FSLocker.ExclusiveLock("setup", &lockTimeout)
	if err != nil {
		return err
	}
	defer exclusiveLock.Unlock()

	ctx, cancel := parentCtx.WithTimeout(maxSetupTime)
	defer cancel()
	// setup interfaces
	err = setupInterfaces(ctx)
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to setup interfaces", 1), err)
	}

	err = waitForInterfaces(ctx)
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Interfaces not available", 1), err)
	}

	// TODO: Ensure interfaces are attached in DeleteOnTermination
	err = setupIFBs(ctx)
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to setup IFBs", 1), err)
	}

	// Setup qdiscs on ENI interfaces
	err = configureQdiscs(ctx)
	if err != nil {
		return cli.NewMultiError(cli.NewExitError("Unable to setup qdiscs", 1), err)
	}
	return nil
}

// TODO: Wrap in CLI errrors
func setupInterfaces(ctx *context.VPCContext) error {
	allInterfaces, err := ctx.EC2metadataClientWrapper.Interfaces()
	if err != nil {
		return err
	}

	// We're "setup" here, go on
	if vpc.GetMaxInterfaces(ctx.InstanceType) == len(allInterfaces) {
		return nil
	}
	ctx.Logger.Infof("%d interfaces missing, adding them", vpc.GetMaxInterfaces(ctx.InstanceType)-len(allInterfaces))

	interfaceByIdx := make(map[int]ec2wrapper.NetworkInterface)

	for _, networkInterface := range allInterfaces {
		interfaceByIdx[networkInterface.GetDeviceNumber()] = networkInterface
	}

	defaultMac, err := ctx.EC2metadataClientWrapper.PrimaryInterfaceMac()
	if err != nil {
		return err
	}
	defaultInterface, ok := allInterfaces[defaultMac]
	if !ok {
		ctx.Logger.Warning("Unable to find default interface")
		return errors.New("Unable to find default interface")
	}
	subnetID := defaultInterface.GetSubnetID()

	// Ignore interface device index 0 -- that's always the default network adapter
	for i := 1; i < vpc.GetMaxInterfaces(ctx.InstanceType); i++ {
		if _, ok := interfaceByIdx[i]; !ok {
			err = attachInterfaceAtIdx(ctx, ctx.InstanceID, subnetID, i)
			if err != nil {
				ctx.Logger.Warning("Unable to attach interface: ", err)
				return err
			}
		}
	}

	return nil
}

func attachInterfaceAtIdx(ctx *context.VPCContext, instanceID, subnetID string, idx int) error {
	ctx.Logger.WithField("idx", idx).Info("Attaching interface")
	// TODO: Check DescribeInstances to make sure an existing interface is not in attaching
	svc := ec2.New(ctx.AWSSession)

	createNetworkInterfaceInput := &ec2.CreateNetworkInterfaceInput{
		Description:      aws.String(vpc.NetworkInterfaceDescription),
		SubnetId:         aws.String(subnetID),
		Ipv6AddressCount: aws.Int64(int64(vpc.GetMaxIPv6Addresses(ctx.InstanceType))),
	}
	createNetworkInterfaceResult, err := svc.CreateNetworkInterfaceWithContext(ctx, createNetworkInterfaceInput)
	if err != nil {
		return err
	}

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
	_, err = svc.CreateTagsWithContext(ctx, createTagsInput)
	if err != nil {
		return err
	}

	attachNetworkInterfaceInput := &ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        aws.Int64(int64(idx)),
		InstanceId:         aws.String(instanceID),
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}
	// TODO: Delete interface if attaching fails.
	attachNetworkInterfaceResult, err := svc.AttachNetworkInterfaceWithContext(ctx, attachNetworkInterfaceInput)
	if err != nil {
		return err
	}

	modifyNetworkInterfaceAttributeInput := &ec2.ModifyNetworkInterfaceAttributeInput{
		Attachment: &ec2.NetworkInterfaceAttachmentChanges{
			AttachmentId:        attachNetworkInterfaceResult.AttachmentId,
			DeleteOnTermination: aws.Bool(true),
		},
		NetworkInterfaceId: createNetworkInterfaceResult.NetworkInterface.NetworkInterfaceId,
	}
	_, err = svc.ModifyNetworkInterfaceAttributeWithContext(ctx, modifyNetworkInterfaceAttributeInput)
	return err
}

func waitForInterfaces(ctx *context.VPCContext) error {
	waitUntil := time.Now().Add(time.Minute)
	for time.Until(waitUntil) > 0 {
		allInterfaces, err := ctx.EC2metadataClientWrapper.Interfaces()
		if err != nil {
			return err
		}
		if vpc.GetMaxInterfaces(ctx.InstanceType) == len(allInterfaces) {
			return waitForInterfacesUp(ctx, allInterfaces)
		}
		time.Sleep(5 * time.Second)
	}
	return errors.New("All interfaces not seen via metadata service")
}

func waitForInterfacesUp(ctx *context.VPCContext, allInterfaces map[string]ec2wrapper.NetworkInterface) error {
	waitUntil := time.Now().Add(time.Minute)

	for time.Until(waitUntil) > 0 {
		ctx.Logger.Info("Waiting for interfaces to come up")
		outstandingInterfaces := len(allInterfaces)
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, i := range interfaces {
			if _, ok := allInterfaces[i.HardwareAddr.String()]; !ok {
				// Not an ENI
				continue
			}
			if i.Flags&net.FlagUp > 0 {
				outstandingInterfaces--
			}
		}
		if outstandingInterfaces == 0 {
			return nil
		}
		ctx.Logger.WithField("outstandingInterfaces", outstandingInterfaces).Info("Not all interfaces up")
		time.Sleep(5 * time.Second)
	}

	return errors.New("Not all interfaces attached and up")
}
