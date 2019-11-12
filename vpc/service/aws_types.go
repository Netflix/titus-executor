package service

import (
	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
)

// Convenience functions for converting between AWS types and protobuf types

func networkInterface(ni ec2.NetworkInterface) *vpcapi.NetworkInterface {
	tni := &vpcapi.NetworkInterface{
		AvailabilityZone:   aws.StringValue(ni.AvailabilityZone),
		MacAddress:         aws.StringValue(ni.MacAddress),
		NetworkInterfaceId: aws.StringValue(ni.NetworkInterfaceId),
		OwnerAccountId:     aws.StringValue(ni.OwnerId),
		VpcId:              aws.StringValue(ni.VpcId),
	}
	if ni.Attachment != nil {
		tni.NetworkInterfaceAttachment = &vpcapi.NetworkInterfaceAttachment{
			DeviceIndex: uint32(*ni.Attachment.DeviceIndex),
		}
	}
	return tni
}

func networkInterfaces(nis []*ec2.NetworkInterface) []*vpcapi.NetworkInterface {
	interfaces := make([]*vpcapi.NetworkInterface, len(nis))
	for idx := range nis {
		interfaces[idx] = networkInterface(*nis[idx])
	}
	return interfaces
}

func instanceNetworkInterface(instance ec2.Instance, ni ec2.InstanceNetworkInterface) *vpcapi.NetworkInterface {
	az := instance.Placement.AvailabilityZone
	tni := &vpcapi.NetworkInterface{
		SubnetId:           *ni.SubnetId,
		AvailabilityZone:   *az,
		MacAddress:         *ni.MacAddress,
		NetworkInterfaceId: *ni.NetworkInterfaceId,
		OwnerAccountId:     *ni.OwnerId,
		NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{
			DeviceIndex: uint32(*ni.Attachment.DeviceIndex),
		},
	}

	return tni
}

func instanceNetworkInterfaces(instance ec2.Instance, nis []*ec2.InstanceNetworkInterface) []*vpcapi.NetworkInterface {
	interfaces := make([]*vpcapi.NetworkInterface, len(nis))
	for idx := range nis {
		interfaces[idx] = instanceNetworkInterface(instance, *nis[idx])
	}
	return interfaces
}
