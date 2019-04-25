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
	// ErrorInterfaceCorrupted indicates the data that EC2 returned to us was invalid
	ErrorInterfaceCorrupted = errors.New("Interface data corrupted")
)

type cacheType string

const (
	interfaceKey cacheType = "interfaces"
	subnetKey    cacheType = "subnets"
)

// Cache is a state dir (/run, memory) backed cache
type Cache struct {
	fslocker *fslocker.FSLocker
	stateDir string
}

func newCache(fslocker *fslocker.FSLocker, statePath string) (*Cache, error) {
	sc := &Cache{
		fslocker: fslocker,
		stateDir: statePath,
	}
	err := os.MkdirAll(sc.getPersistedPath(interfaceKey, ""), 0700)
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(sc.getPersistedPath(subnetKey, ""), 0700)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// DescribeSubnet fetches the subnet from cache, or EC2, and automatically persists it to the persistent cache
func (sc *Cache) DescribeSubnet(parentCtx *VPCContext, subnetid string) (*ec2.Subnet, error) {
	timeout := 30 * time.Second
	ctx, cancel := parentCtx.WithField("subnetid", subnetid).WithTimeout(30 * time.Second)
	defer cancel()
	lockPath := fmt.Sprintf("subnets/%s", subnetid)
	exclusiveLock, err := sc.fslocker.ExclusiveLock(lockPath, &timeout)
	if err != nil {
		ctx.Logger.Warning("Subnet cache unable to retrieve subnet information")
		return nil, err
	}
	defer exclusiveLock.Unlock()

	subnet, err := sc.fetchSubnetFromCache(ctx, subnetid)
	if err != nil {
		return nil, err
	}
	if subnet != nil {
		ctx.Logger.Info("Subnet successfully loaded from cache")
		return subnet, err
	}
	subnet, err = sc.fetchSubnetFromEC2(ctx, subnetid)
	if err != nil {
		ctx.Logger.Info("Subnet successfully loaded from EC2")
		return nil, err
	}
	sc.persistSubnetToCache(ctx, *subnet)

	return subnet, nil
}

// DescribeInterface interface the subnet from cache, or EC2, and automatically persists it to the persistent cache.
// since interfaces are mutable IT SHOULD BE USED WITH CARE, and should not be used to access mutable interface
// attributes
func (sc *Cache) DescribeInterface(parentCtx *VPCContext, eniID string) (*ec2.NetworkInterface, error) {
	timeout := 30 * time.Second
	ctx, cancel := parentCtx.WithField("eniID", eniID).WithTimeout(timeout)
	defer cancel()
	lockPath := fmt.Sprintf("interfaces/%s", eniID)
	exclusiveLock, err := sc.fslocker.ExclusiveLock(lockPath, &timeout)
	if err != nil {
		ctx.Logger.Warning("Subnet cache unable to retrieve subnet information")
		return nil, err
	}
	defer exclusiveLock.Unlock()

	iface, err := sc.fetchInterfaceFromCache(ctx, eniID)
	if err != nil {
		return nil, err
	}
	if iface != nil {
		ctx.Logger.Info("Interface successfully loaded from cache")
		return iface, err
	}
	iface, err = sc.fetchInterfaceFromEC2(ctx, eniID)
	if err != nil {
		ctx.Logger.Info("Interface successfully loaded from EC2")
		return nil, err
	}
	sc.persistInterfaceToCache(ctx, *iface)

	return iface, nil
}

func (sc *Cache) fetchInterfaceFromCache(ctx *VPCContext, eniID string) (*ec2.NetworkInterface, error) {
	path := sc.getPersistedPath(interfaceKey, eniID)
	bytes, err := ioutil.ReadFile(path) // nolint: gosec
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var iface ec2.NetworkInterface
	err = json.Unmarshal(bytes, &iface)
	if err != nil {
		return nil, err
	}
	return &iface, nil
}

func (sc *Cache) fetchSubnetFromCache(ctx *VPCContext, subnetid string) (*ec2.Subnet, error) {
	path := sc.getPersistedPath(subnetKey, subnetid)
	bytes, err := ioutil.ReadFile(path) // nolint: gosec
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

func (sc *Cache) fetchSubnetFromEC2(ctx *VPCContext, subnetid string) (*ec2.Subnet, error) {
	describeSubnetsInput := &ec2.DescribeSubnetsInput{
		SubnetIds: []*string{aws.String(subnetid)},
	}
	subnetOutput, err := ec2.New(ctx.AWSSession).DescribeSubnetsWithContext(ctx, describeSubnetsInput)
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

func (sc *Cache) fetchInterfaceFromEC2(ctx *VPCContext, eniID string) (*ec2.NetworkInterface, error) {
	describeNetworkInterfacesInput := &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{aws.String(eniID)},
	}
	describeNetworkInterfacesOutput, err := ec2.New(ctx.AWSSession).DescribeNetworkInterfacesWithContext(ctx, describeNetworkInterfacesInput)
	if err != nil {
		return nil, err
	}
	if len(describeNetworkInterfacesOutput.NetworkInterfaces) != 1 {
		return nil, ErrorSubnetNotFound
	}
	iface := describeNetworkInterfacesOutput.NetworkInterfaces[0]
	if (*iface.NetworkInterfaceId) != eniID || (*iface.MacAddress) == "" {
		return nil, ErrorInterfaceCorrupted
	}

	return iface, nil
}

func (sc *Cache) persistInterfaceToCache(ctx *VPCContext, iface ec2.NetworkInterface) {
	sc.persistToCache(ctx, interfaceKey, *iface.NetworkInterfaceId, iface)
}

func (sc *Cache) persistSubnetToCache(ctx *VPCContext, subnet ec2.Subnet) {
	if *subnet.State != "available" {
		ctx.Logger.Warning("Not persisting subnet because not available")
		return
	}
	sc.persistToCache(ctx, subnetKey, *subnet.SubnetId, subnet)
}

func (sc *Cache) persistToCache(ctx *VPCContext, itemType cacheType, id string, item interface{}) {
	// We should be holding an exclusive lock on the subnet ID at this point
	path := sc.getPersistedPath(itemType, id)
	bytes, err := json.Marshal(item)
	if err != nil {
		ctx.Logger.Error("Unable to marshal subnet for caching: ", err)
		return
	}
	err = atomicWriteOnce(path, bytes)
	if err != nil {
		ctx.Logger.Error("Unable to write subnet data: ", err)
		return
	}
	ctx.Logger.Info("Subnet successfully persisted to cache")
}

func shouldClose(closer io.Closer) error {
	return closer.Close()
}

func (sc *Cache) getPersistedPath(itemType cacheType, id string) string {
	return filepath.Join(sc.stateDir, string(itemType), id)

}
