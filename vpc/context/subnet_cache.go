package context

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

var (
	// ErrorSubnetNotFound indicates EC2 didn't return exactly one subnet
	ErrorSubnetNotFound = errors.New("Subnet not found")
	// ErrorSubnetCorrupted indicates the data that EC2 returned to us was invalid
	ErrorSubnetCorrupted = errors.New("Subnet data corrupted")
)

// SubnetCache is a state dir (/run, memory) backed cache
type SubnetCache struct {
	fslocker *fslocker.FSLocker
	stateDir string
}

func newSubnetCache(fslocker *fslocker.FSLocker, statePath string) *SubnetCache {
	return &SubnetCache{
		fslocker: fslocker,
		stateDir: statePath,
	}
}

// DescribeSubnet fetches the subnet from cache, or EC2, and automatically persists it to the persistent cache
func (sc *SubnetCache) DescribeSubnet(parentCtx VPCContext, subnetid string) (*ec2.Subnet, error) {
	timeout := 30 * time.Second
	ctx, cancel := parentCtx.WithField("subnetid", subnetid).WithTimeout(30 * time.Second)
	defer cancel()
	lockPath := fmt.Sprintf("subnets/%s", subnetid)
	exclusiveLock, err := sc.fslocker.ExclusiveLock(lockPath, &timeout)
	if err != nil {
		ctx.Logger().Warning("Subnet cache unable to retrieve subnet information")
		return nil, err
	}
	defer exclusiveLock.Unlock()

	subnet, err := sc.fetchFromCache(ctx, subnetid)
	if err != nil {
		return nil, err
	}
	if subnet != nil {
		ctx.Logger().Info("Subnet successfully loaded from cache")
		return subnet, err
	}
	subnet, err = sc.fetchFromEC2(ctx, subnetid)
	if err != nil {
		ctx.Logger().Info("Subnet successfully loaded from EC2")
		return nil, err
	}
	sc.persistToCache(ctx, *subnet)

	return subnet, nil
}

func (sc *SubnetCache) fetchFromCache(ctx VPCContext, subnetid string) (*ec2.Subnet, error) {
	path := filepath.Join(sc.stateDir, subnetid)
	bytes, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var subnet ec2.Subnet
	err = json.Unmarshal(bytes, &subnet)
	if err != nil {
		return nil, err
	}
	return &subnet, nil
}

func (sc *SubnetCache) fetchFromEC2(ctx VPCContext, subnetid string) (*ec2.Subnet, error) {
	describeSubnetsInput := &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{aws.String(subnetid)},
	}
	subnetOutput, err := ec2.New(ctx).DescribeSubnetsWithContext(ctx, describeSubnetsInput)
	if err != nil {
		return nil, err
	}
	if len(subnetOutput.Subnets) != 1 {
		return nil, ErrorSubnetNotFound
	}
	subnet := subnetOutput.Subnets[0]
	if (*subnet.SubnetId) != subnetid || (*subnet.CidrBlock) == "" {
		return nil, ErrorSubnetCorrupted
	}

	return subnet, nil
}

func (sc *SubnetCache) persistToCache(ctx VPCContext, subnet ec2.Subnet) {
	if *subnet.State != "available" {
		ctx.Logger().Warning("Not persisting subnet because not available")
		return
	}

	// We should be holding an exclusive lock on the subnet ID at this point
	path := filepath.Join(sc.stateDir, *subnet.SubnetId)
	bytes, err := json.Marshal(subnet)
	if err != nil {
		ctx.Logger().Error("Unable to marshal subnet for caching: ", err)
		return
	}
	err = atomicWriteOnce(path, bytes)
	if err != nil {
		ctx.Logger().Error("Unable to write subnet data: ", err)
		return
	}
	ctx.Logger().Info("Subnet successfully persisted to cache")
}

func shouldClose(closer io.Closer) {
	_ = closer.Close()
}
