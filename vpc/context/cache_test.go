package context

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSubnetName1  = "testsubnet"
	testSubnetName2  = "not-available-subnet"
	testInterfaceID1 = "test-id1"
)

func TestSubnetCache(t *testing.T) {
	testContext := newTestContext()
	tempdir, err := ioutil.TempDir("", "subnet-cache")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(tempdir))
	}()
	fsLockerDir := filepath.Join(tempdir, "fslocker")
	cacheDir := filepath.Join(tempdir, "cache")
	fsl, err := fslocker.NewFSLocker(fsLockerDir)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cacheDir, 0700))
	subnetCache, err := newCache(fsl, cacheDir)
	require.NoError(t, err)
	subnet1, err := subnetCache.fetchSubnetFromCache(testContext, testSubnetName1)
	assert.NoError(t, err)
	assert.Nil(t, subnet1)

	// Persist and retrieve subnet
	fakeSubnet1 := ec2.Subnet{
		AvailabilityZone:        aws.String("us-east-1a"),
		CidrBlock:               aws.String("1.2.3.0/24"),
		SubnetId:                aws.String(testSubnetName1),
		AvailableIpAddressCount: aws.Int64(32),
		State: aws.String("available"),
	}
	subnetCache.persistSubnetToCache(testContext, fakeSubnet1)

	subnet2, err := subnetCache.fetchSubnetFromCache(testContext, testSubnetName1)
	assert.NoError(t, err)
	assert.EqualValues(t, fakeSubnet1.AvailabilityZone, subnet2.AvailabilityZone)
	assert.EqualValues(t, fakeSubnet1.CidrBlock, subnet2.CidrBlock)
	assert.EqualValues(t, fakeSubnet1.SubnetId, subnet2.SubnetId)
	assert.EqualValues(t, fakeSubnet1.AvailableIpAddressCount, subnet2.AvailableIpAddressCount)
	assert.EqualValues(t, fakeSubnet1.State, subnet2.State)

	// Make sure we don't persist non-available subnets
	fakeSubnet2 := ec2.Subnet{
		State: aws.String("not-available"),
	}
	subnetCache.persistSubnetToCache(testContext, fakeSubnet2)

	subnet3, err := subnetCache.fetchSubnetFromCache(testContext, testSubnetName2)
	assert.NoError(t, err)
	assert.Nil(t, subnet3)
}

func TestInterfaceCache(t *testing.T) {
	testContext := newTestContext()
	tempdir, err := ioutil.TempDir("", "interface-cache")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, os.RemoveAll(tempdir))
	}()
	fsLockerDir := filepath.Join(tempdir, "fslocker")
	cacheDir := filepath.Join(tempdir, "cache")
	fsl, err := fslocker.NewFSLocker(fsLockerDir)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cacheDir, 0700))
	subnetCache, err := newCache(fsl, cacheDir)
	require.NoError(t, err)
	iface1, err := subnetCache.fetchSubnetFromCache(testContext, testInterfaceID1)
	assert.NoError(t, err)
	assert.Nil(t, iface1)

	// Persist and retrieve subnet
	fakeInterface1 := ec2.NetworkInterface{
		MacAddress:         aws.String("abc"),
		NetworkInterfaceId: aws.String(testInterfaceID1),
	}
	subnetCache.persistInterfaceToCache(testContext, fakeInterface1)

	iface, err := subnetCache.fetchInterfaceFromCache(testContext, testInterfaceID1)
	assert.NoError(t, err)
	assert.EqualValues(t, iface.MacAddress, fakeInterface1.MacAddress)
	assert.EqualValues(t, iface.NetworkInterfaceId, fakeInterface1.NetworkInterfaceId)

}
