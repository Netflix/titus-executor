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

const testSubnetName1 = "testsubnet"
const testSubnetName2 = "not-available-subnet"

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
	subnetCache := newSubnetCache(fsl, cacheDir)
	subnet1, err := subnetCache.fetchFromCache(testContext, testSubnetName1)
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
	subnetCache.persistToCache(testContext, fakeSubnet1)

	subnet2, err := subnetCache.fetchFromCache(testContext, testSubnetName1)
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
	subnetCache.persistToCache(testContext, fakeSubnet2)

	subnet3, err := subnetCache.fetchFromCache(testContext, testSubnetName2)
	assert.NoError(t, err)
	assert.Nil(t, subnet3)
}
