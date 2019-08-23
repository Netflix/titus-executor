package service

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

type fakeEC2NetworkInterfaceSession struct {
	iface                               *ec2.NetworkInterface
	lastUnassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput
}

func (f fakeEC2NetworkInterfaceSession) ElasticNetworkInterfaceID() string {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) Session(ctx context.Context) (*session.Session, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) GetSubnet(ctx context.Context, strategy ec2wrapper.CacheStrategy) (*ec2.Subnet, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) GetSubnetByID(ctx context.Context, subnetID string, strategy ec2wrapper.CacheStrategy) (*ec2.Subnet, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) GetDefaultSecurityGroups(ctx context.Context) ([]*string, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) ModifySecurityGroups(ctx context.Context, groupIds []*string) error {
	panic("implement me")
}

func (f fakeEC2NetworkInterfaceSession) GetNetworkInterface(ctx context.Context, duration time.Duration) (*ec2.NetworkInterface, error) {
	return f.iface, nil
}

func (fakeEC2NetworkInterfaceSession) AssignPrivateIPAddresses(ctx context.Context, assignPrivateIPAddressesInput ec2.AssignPrivateIpAddressesInput) (*ec2.AssignPrivateIpAddressesOutput, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) AssignIPv6Addresses(ctx context.Context, assignIpv6AddressesInput ec2.AssignIpv6AddressesInput) (*ec2.AssignIpv6AddressesOutput, error) {
	panic("implement me")
}

func (f *fakeEC2NetworkInterfaceSession) UnassignPrivateIPAddresses(ctx context.Context, unassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput) (*ec2.UnassignPrivateIpAddressesOutput, error) {
	f.lastUnassignPrivateIPAddressesInput = unassignPrivateIPAddressesInput
	return nil, nil
}

func TestIPsToFree(t *testing.T) {
	logruslogger := logrus.New()
	logruslogger.SetLevel(logrus.DebugLevel)
	ctx := logger.WithLogger(context.Background(), logruslogger)

	fiveMinutesAgo, err := ptypes.TimestampProto(time.Now().Add(-5 * time.Minute))
	assert.NilError(t, err)
	now := ptypes.TimestampNow()

	req := &vpcapi.GCRequest{
		CacheVersion:               nil,
		InstanceIdentity:           nil,
		NetworkInterfaceAttachment: nil,
		UnallocatedAddresses: []*vpcapi.UtilizedAddress{
			{
				Address: &vpcapi.Address{
					Address: "10.0.0.1",
				},
				LastUsedTime: fiveMinutesAgo,
			},
			{
				Address: &vpcapi.Address{
					Address: "192.168.1.0",
				},
				LastUsedTime: fiveMinutesAgo,
			},
			{
				Address: &vpcapi.Address{
					Address: "192.168.1.10",
				},
				LastUsedTime: fiveMinutesAgo,
			},
			{
				Address: &vpcapi.Address{
					Address: "192.168.1.86",
				},
				LastUsedTime: fiveMinutesAgo,
			},
			{
				Address: &vpcapi.Address{
					Address: "192.168.1.55",
				},
				LastUsedTime: now,
			},
		},
		NonviableAddresses: []*vpcapi.UtilizedAddress{},
		AllocatedAddresses: []*vpcapi.UtilizedAddress{
			// This shouldn't be deleted, because it was just added
			{
				Address: &vpcapi.Address{
					Address: "192.168.1.0",
				},
				LastUsedTime: now,
			},
			{
				Address: &vpcapi.Address{
					Address: "192.168.1.5",
				},
				LastUsedTime: now,
			},
			{
				// Should not be freed, even though it's not attached to the ENI. The reason is that the ENI state
				// could be cached.
				Address: &vpcapi.Address{
					Address: "192.168.1.111",
				},
				LastUsedTime: now,
			},
		},
	}

	ec2NetworkInterfaceSession := &fakeEC2NetworkInterfaceSession{
		iface: &ec2.NetworkInterface{
			Ipv6Addresses:    nil,
			PrivateIpAddress: aws.String("192.168.1.0"),
			PrivateIpAddresses: []*ec2.NetworkInterfacePrivateIpAddress{
				{
					Primary:          aws.Bool(false),
					PrivateIpAddress: aws.String("192.168.1.1"),
				},
				{
					Primary:          aws.Bool(false),
					PrivateIpAddress: aws.String("192.168.1.2"),
				},
				{
					Primary:          aws.Bool(false),
					PrivateIpAddress: aws.String("192.168.1.5"),
				},
				{
					Primary:          aws.Bool(false),
					PrivateIpAddress: aws.String("192.168.1.10"),
				},
			},
		},
	}
	resp, err := gcInterface(ctx, ec2NetworkInterfaceSession, req, time.Minute*2)
	assert.NilError(t, err)

	sort.Slice(resp.AddressToDelete, func(i, j int) bool {
		return resp.AddressToDelete[i].Address < resp.AddressToDelete[j].Address
	})

	sort.Slice(resp.AddressToBump, func(i, j int) bool {
		return resp.AddressToBump[i].Address < resp.AddressToBump[j].Address
	})

	addressesToBump := []*vpcapi.Address{
		{
			// Bumped, because assigned to the interface, but not in the unallocated, nor allocated list
			Address: "192.168.1.1",
		},
		{
			// Bumped, because assigned to the interface, but not in the unallocated, nor allocated list
			Address: "192.168.1.2",
		},
	}
	assert.DeepEqual(t, addressesToBump, resp.AddressToBump)

	addressesToDelete := []*vpcapi.Address{
		{
			// Deleted because never part of interface configuration
			Address: "10.0.0.1",
		},
		{
			// Deleted (and freed), because unallocated for more than 2 minutes
			Address: "192.168.1.10",
		},
		{
			// Deleted , because unallocated for more than 2 minutes
			Address: "192.168.1.86",
		},
	}
	assert.DeepEqual(t, addressesToDelete, resp.AddressToDelete)

	assert.DeepEqual(t, ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses, aws.StringSlice([]string{"192.168.1.10"}))

	//	assert.DeepEqual(t, ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses, aws.StringSlice([]string{"192.168.1.10"}))
	//	assert.Assert(t, is.Len(ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses, 1))
	//	assert.Assert(t, is.Contains(aws.StringValueSlice(ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses), "192.168.1.10"))
}
