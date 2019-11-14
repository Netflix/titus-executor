package service

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	set "github.com/deckarep/golang-set"
	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
)

func setToSlice(s set.Set) []string {
	out := []string{}
	for item := range s.Iter() {
		out = append(out, item.(string))

	}
	sort.Strings(out)
	return out
}

func sortStringSlice(s []string) []string {
	sort.Strings(s)
	return s
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

	iface := &ec2.NetworkInterface{
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
	}
	calculation, err := calculateGcInterface(ctx, iface, req, time.Minute*2)
	assert.NilError(t, err)

	addressesToBump := sortStringSlice([]string{

		// Bumped, because assigned to the interface, but not in the unallocated, nor allocated list
		"192.168.1.1",

		// Bumped, because assigned to the interface, but not in the unallocated, nor allocated list
		"192.168.1.2",
	})

	assert.DeepEqual(t, addressesToBump, setToSlice(calculation.addressesToBumpSet))

	addressesToDelete := sortStringSlice([]string{
		// Deleted because never part of interface configuration
		"10.0.0.1",
		// Deleted (and freed), because unallocated for more than 2 minutes
		"192.168.1.10",
		// Deleted , because unallocated for more than 2 minutes
		"192.168.1.86",
	})
	assert.DeepEqual(t, addressesToDelete, setToSlice(calculation.addressesToDeleteSet))

	assert.DeepEqual(t, setToSlice(calculation.ipsToFreeSet), sortStringSlice([]string{"192.168.1.10"}))

	//	assert.DeepEqual(t, ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses, aws.StringSlice([]string{"192.168.1.10"}))
	//	assert.Assert(t, is.Len(ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses, 1))
	//	assert.Assert(t, is.Contains(aws.StringValueSlice(ec2NetworkInterfaceSession.lastUnassignPrivateIPAddressesInput.PrivateIpAddresses), "192.168.1.10"))

}
