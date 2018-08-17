package ec2wrapper

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	set "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"
)

// EC2MetadataClientWrapper wraps the EC2 library and provides some helper functions
type EC2MetadataClientWrapper struct {
	ec2metadata *ec2metadata.EC2Metadata
	logger      *logrus.Entry
}

// EC2NetworkInterface encapsulates information about network interfaces
type EC2NetworkInterface struct {
	mdc *EC2MetadataClientWrapper
	// DeviceNumber is the AWS / EC2 device index, it should correlate to eth${DEVICEIDX}
	DeviceNumber int
	// InterfaceID is the ENI ID
	InterfaceID string
	// SubnetID is the Id of the subnet which the interface is in
	SubnetID string
	// MAC is the mac address in fully expanded form, i.e. 00:00:00:00:00:00
	MAC string
	// SecurityGroupIds is the set of SGs (IDs) on the interface
	SecurityGroupIds map[string]struct{}
	// We don't use type net.IP here, because the same IP can end up being duplicated as a key
	// even though they're equal
	// IPv4Addresses is the set of currently assigned IPs -- The primary IPv4 address is the first in this list
	IPv4Addresses []string
	// TODO: Add IPv6 addresses
}

// NewEC2MetadataClientWrapper creates a new ec2metadata wrapper instance
func NewEC2MetadataClientWrapper(session client.ConfigProvider, logger *logrus.Entry) *EC2MetadataClientWrapper {
	return &EC2MetadataClientWrapper{
		ec2metadata: ec2metadata.New(session),
		logger:      logger,
	}
}

// PrimaryInterfaceMac returns the mac of the primary interface
func (mdc *EC2MetadataClientWrapper) PrimaryInterfaceMac() (string, error) {
	val, err := mdc.getMetadata("mac")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(val), nil
}

// InstanceID returns the i- of the instance
func (mdc *EC2MetadataClientWrapper) InstanceID() (string, error) {
	val, err := mdc.getMetadata("instance-id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(val), nil

}

// AvailabilityZone returns the qualified availability zone of the instance
func (mdc *EC2MetadataClientWrapper) AvailabilityZone() (string, error) {
	val, err := mdc.getMetadata("placement/availability-zone")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(val), nil
}

// Interfaces returns a map of mac addresses to interfaces
func (mdc *EC2MetadataClientWrapper) Interfaces() (map[string]EC2NetworkInterface, error) {
	ret := make(map[string]EC2NetworkInterface)
	val, err := mdc.getMetadata("network/interfaces/macs/")
	if err != nil {
		return ret, err
	}

	for _, mac := range strings.Split(strings.TrimSpace(val), "\n") {
		actualMac := strings.TrimRight(mac, "/")
		ret[actualMac], err = mdc.GetInterface(actualMac)
		if err != nil {
			return ret, err
		}
	}

	return ret, nil
}

// GetInterface fetches a populated interface by mac address
func (mdc *EC2MetadataClientWrapper) GetInterface(mac string) (EC2NetworkInterface, error) {
	ret := EC2NetworkInterface{
		MAC: mac,
		mdc: mdc,
	}

	devNumberString, err := mdc.getDataForInterface(mac, "device-number")
	if err != nil {
		return ret, err
	}

	ret.DeviceNumber, err = strconv.Atoi(devNumberString)
	if err != nil {
		return ret, err
	}

	ret.InterfaceID, err = mdc.getDataForInterface(mac, "interface-id")
	if err != nil {
		return ret, err
	}

	ret.SubnetID, err = mdc.getDataForInterface(mac, "subnet-id")
	if err != nil {
		return ret, err
	}

	return ret, ret.Refresh()
}

func (mdc *EC2MetadataClientWrapper) getDataForInterface(mac, data string) (string, error) {
	path := fmt.Sprintf("network/interfaces/macs/%s/%s", mac, data)
	str, err := mdc.getMetadata(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(str), err
}

func (mdc *EC2MetadataClientWrapper) getMetadata(path string) (string, error) {
	var val string
	var err error
	for i := 0; i < 10; i++ {
		val, err = mdc.ec2metadata.GetMetadata(path)
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "429") {
			// Sleep a minimum of 10 milliseconds, and up to 100 ms
			jitter := time.Millisecond * time.Duration(rand.Intn(90)+10)
			time.Sleep(jitter)
		} else {
			// "Fatal error"
			break
		}
	}
	if err != nil {
		mdc.logger.WithField("path", path).Warning("Error while fetching metadata: ", err)
	}
	return val, err
}

// Refresh updates the security groups. and local IPv4 addresses for an interface
func (ni *EC2NetworkInterface) Refresh() error {
	ni.SecurityGroupIds = make(map[string]struct{})

	securityGroupIdsString, err := ni.mdc.getDataForInterface(ni.MAC, "security-group-ids")
	if err != nil {
		return err
	}
	for _, sgID := range strings.Split(securityGroupIdsString, "\n") {
		ni.SecurityGroupIds[sgID] = struct{}{}
	}

	localIPv4s, err := ni.mdc.getDataForInterface(ni.MAC, "local-ipv4s")
	if err != nil {
		return err
	}
	ni.IPv4Addresses = strings.Split(localIPv4s, "\n")
	for idx, addr := range ni.IPv4Addresses {
		ni.IPv4Addresses[idx] = strings.Trim(strings.TrimSpace(addr), "\x00")
	}

	return nil
}

// LockPath returns the path you should use for locks on this interface
func (ni *EC2NetworkInterface) LockPath() string {
	return filepath.Join("interfaces", ni.MAC)
}

// IPv4AddressesAsSet returns a copy of the IPv4Addresses from this network interface as a set
func (ni *EC2NetworkInterface) IPv4AddressesAsSet() set.Set {
	s := set.NewThreadUnsafeSet()
	for _, ip := range ni.IPv4Addresses {
		s.Add(ip)
	}
	return s
}
