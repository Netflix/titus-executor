package service

import (
	"context"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

type fakeEC2NetworkInterfaceSession struct {
	iface                               *ec2.NetworkInterface
	lastUnassignPrivateIPAddressesInput ec2.UnassignPrivateIpAddressesInput
}

func (fakeEC2NetworkInterfaceSession) Session(ctx context.Context) (*session.Session, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) GetSubnet(ctx context.Context) (*ec2.Subnet, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) GetSubnetByID(ctx context.Context, subnetID string) (*ec2.Subnet, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) GetDefaultSecurityGroups(ctx context.Context) ([]*string, error) {
	panic("implement me")
}

func (fakeEC2NetworkInterfaceSession) ModifySecurityGroups(ctx context.Context, groupIds []*string) error {
	panic("implement me")
}

func (f fakeEC2NetworkInterfaceSession) GetNetworkInterface(ctx context.Context) (*ec2.NetworkInterface, error) {
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

	fiveMinutesAgo := timestamp.Timestamp{
		Seconds: int64(time.Now().Add(-5 * time.Minute).Second()),
		Nanos:   0,
	}
	now := timestamp.Timestamp{
		Seconds: int64(time.Now().Second()),
		Nanos:   0,
	}
	req := &vpcapi.GCRequest{
		CacheVersion:               nil,
		InstanceIdentity:           nil,
		NetworkInterfaceAttachment: nil,
		UnallocatedAddresses: []*vpcapi.UtilizedAddress{
			{
				Address: &titus.Address{
					Address: "10.0.0.1",
				},
				LastUsedTime: &fiveMinutesAgo,
			},
			{
				Address: &titus.Address{
					Address: "192.168.1.0",
				},
				LastUsedTime: &fiveMinutesAgo,
			},
			{
				Address: &titus.Address{
					Address: "192.168.1.10",
				},
				LastUsedTime: &fiveMinutesAgo,
			},
		},
		NonviableAddresses: []*vpcapi.UtilizedAddress{
			// This shouldn't be deleted, because it was just added
			{
				Address: &titus.Address{
					Address: "192.168.1.2",
				},
				LastUsedTime: &now,
			},
		},
		AllocatedAddresses: []*vpcapi.UtilizedAddress{
			// This shouldn't be deleted, because it was just added
			{
				Address: &titus.Address{
					Address: "192.168.1.5",
				},
				LastUsedTime: &fiveMinutesAgo,
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
	resp, err := gcInterface(ctx, ec2NetworkInterfaceSession, req)
	t.Log(resp)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(resp.AddressToBump, 1))
	assert.Assert(t, is.Contains(resp.AddressToBump, &titus.Address{
		Address: "192.168.1.1",
	}))

	assert.Assert(t, is.Len(resp.AddressToDelete, 2))
	assert.Assert(t, is.Contains(resp.AddressToDelete, &titus.Address{
		Address: "10.0.0.1",
	}))
	assert.Assert(t, is.Contains(resp.AddressToDelete, &titus.Address{
		Address: "192.168.1.10",
	}))

	assert.Assert(t, is.Len(ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses, 1))
	assert.Assert(t, is.Contains(aws.StringValueSlice(ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses), "192.168.1.10"))
}
