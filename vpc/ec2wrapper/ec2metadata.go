package ec2wrapper

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/ec2"
	set "github.com/deckarep/golang-set"
	"github.com/sirupsen/logrus"
)

// IPAssignmentFunction calls AWS to assign IP addresses to this interface
type IPAssignmentFunction func(ctx context.Context, session client.ConfigProvider, count int) error

// IPFetchFunction tells us what IPs are currently assigned to this interface. It may require refresh to be called to
// get updated information
type IPFetchFunction func() []string

type ec2MetadataClient interface {
	Available() bool
	GetDynamicData(p string) (string, error)
	GetInstanceIdentityDocument() (ec2metadata.EC2InstanceIdentityDocument, error)
	GetMetadata(p string) (string, error)
	GetUserData() (string, error)
	IAMInfo() (ec2metadata.EC2IAMInfo, error)
	Region() (string, error)
}

// EC2MetadataClientWrapper wraps the EC2 library and provides some helper functions
type EC2MetadataClientWrapper struct {
	ec2metadata ec2MetadataClient
	logger      *logrus.Entry
}

// NetworkInterface represents an ENI, or a similar thing
type NetworkInterface interface {
	GetDeviceNumber() int
	GetInterfaceID() string
	GetSubnetID() string
	GetMAC() string
	GetSecurityGroupIds() map[string]struct{}
	GetIPv4Addresses() []string
	GetIPv6Addresses() []string
	AddIPv4Addresses(ctx context.Context, session client.ConfigProvider, count int) error
	AddIPv6Addresses(ctx context.Context, session client.ConfigProvider, count int) error
	Refresh() error
	FreeIPv4Addresses(context.Context, client.ConfigProvider, []string) error
	// TODO: Add IPv6 addresses
}

// EC2NetworkInterface encapsulates information about network interfaces
type EC2NetworkInterface struct {
	mdc *EC2MetadataClientWrapper
	// deviceNumber is the AWS / EC2 device index, it should correlate to eth${DEVICEIDX}
	deviceNumber int
	// interfaceID is the ENI ID
	interfaceID string
	// subnetID is the Id of the subnet which the interface is in
	subnetID string
	// mac is the mac address in fully expanded form, i.e. 00:00:00:00:00:00
	mac string
	// securityGroupIds is the set of SGs (IDs) on the interface
	securityGroupIds map[string]struct{}
	// We don't use type net.IP here, because the same IP can end up being duplicated as a key
	// even though they're equal
	// ipv4Addresses is the set of currently assigned IPs -- The primary IPv4 address is the first in this list
	ipv4Addresses []string

	ipv6Addresses []string
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
func (mdc *EC2MetadataClientWrapper) Interfaces() (map[string]NetworkInterface, error) {
	ret := make(map[string]NetworkInterface)
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
func (mdc *EC2MetadataClientWrapper) GetInterface(mac string) (NetworkInterface, error) {
	ret := &EC2NetworkInterface{
		mac: mac,
		mdc: mdc,
	}

	devNumberString, err := mdc.getDataForInterface(mac, "device-number")
	if err != nil {
		return ret, err
	}

	ret.deviceNumber, err = strconv.Atoi(devNumberString)
	if err != nil {
		return ret, err
	}

	ret.interfaceID, err = mdc.getDataForInterface(mac, "interface-id")
	if err != nil {
		return ret, err
	}

	ret.subnetID, err = mdc.getDataForInterface(mac, "subnet-id")
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
		} else if strings.HasSuffix(path, "ipv6s") && strings.Contains(err.Error(), "404") {
			// This is terrible. The IMDS returns 404 if you have no IPv6 addresses assigned...
			// it seems weird to put this behaviour above this layer, but it also seems like endpoint-specific
			// error handling is weird too?
			return "", nil
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

func ipStringToList(ips string) []string {
	ips = strings.TrimSpace(ips)
	if ips == "" {
		return []string{}
	}
	addresses := strings.Split(ips, "\n")
	result := make([]string, len(addresses))
	for idx, addr := range addresses {
		sanitized := strings.Trim(strings.TrimSpace(addr), "\x00")
		ip := net.ParseIP(sanitized)
		result[idx] = ip.String()
	}
	return result
}

// Refresh updates the security groups. and local IPv4 addresses for an interface
func (ni *EC2NetworkInterface) Refresh() error {
	ni.securityGroupIds = make(map[string]struct{})

	securityGroupIdsString, err := ni.mdc.getDataForInterface(ni.mac, "security-group-ids")
	if err != nil {
		return err
	}
	for _, sgID := range strings.Split(securityGroupIdsString, "\n") {
		ni.securityGroupIds[sgID] = struct{}{}
	}

	localIPv4s, err := ni.mdc.getDataForInterface(ni.mac, "local-ipv4s")
	if err != nil {
		return err
	}

	ni.ipv4Addresses = ipStringToList(localIPv4s)

	localIPv6s, err := ni.mdc.getDataForInterface(ni.mac, "ipv6s")
	if err != nil {
		return err
	}
	ni.ipv6Addresses = ipStringToList(localIPv6s)

	return nil
}

// GetDeviceNumber get the AWS / EC2 device index, it should correlate to eth${DEVICEIDX}
func (ni *EC2NetworkInterface) GetDeviceNumber() int {
	return ni.deviceNumber
}

// GetInterfaceID returns the ENI ID
func (ni *EC2NetworkInterface) GetInterfaceID() string {
	return ni.interfaceID
}

// GetSubnetID gets the Id of the subnet which the interface is in
func (ni *EC2NetworkInterface) GetSubnetID() string {
	return ni.subnetID
}

// GetMAC is the mac address in fully expanded form, i.e. 00:00:00:00:00:00
func (ni *EC2NetworkInterface) GetMAC() string {
	if len(ni.mac) != len("00:00:00:00:00:00") {
		panic("Corrupted mac address")
	}
	return ni.mac
}

// GetSecurityGroupIds is the set of SGs (IDs) on the interface
func (ni *EC2NetworkInterface) GetSecurityGroupIds() map[string]struct{} {
	return ni.securityGroupIds
}

// GetIPv4Addresses is the set of currently assigned IPs -- The primary IPv4 address is the first in this list
func (ni *EC2NetworkInterface) GetIPv4Addresses() []string {
	return ni.ipv4Addresses
}

// GetIPv6Addresses is the set of currently assigned IPv6 IPs
func (ni *EC2NetworkInterface) GetIPv6Addresses() []string {
	return ni.ipv6Addresses
}

// FreeIPv4Addresses calls the EC2 / AWS API to free IP addresses
func (ni *EC2NetworkInterface) FreeIPv4Addresses(ctx context.Context, session client.ConfigProvider, deallocationList []string) error {

	unassignPrivateIPAddressesInput := &ec2.UnassignPrivateIpAddressesInput{
		PrivateIpAddresses: aws.StringSlice(deallocationList),
		NetworkInterfaceId: aws.String(ni.GetInterfaceID()),
	}

	_, err := ec2.New(session).UnassignPrivateIpAddressesWithContext(ctx, unassignPrivateIPAddressesInput)
	return err
}

// AddIPv4Addresses calls the EC2 / AWS API to add IPv4 addresses
func (ni *EC2NetworkInterface) AddIPv4Addresses(ctx context.Context, session client.ConfigProvider, count int) error {
	assignPrivateIPAddressesInput := &ec2.AssignPrivateIpAddressesInput{
		NetworkInterfaceId:             aws.String(ni.GetInterfaceID()),
		SecondaryPrivateIpAddressCount: aws.Int64(int64(count)),
	}

	_, err := ec2.New(session).AssignPrivateIpAddresses(assignPrivateIPAddressesInput)
	return err
}

// AddIPv6Addresses calls the EC2 / AWS API to add IPv6 addresses
func (ni *EC2NetworkInterface) AddIPv6Addresses(ctx context.Context, session client.ConfigProvider, count int) error {
	assignPrivateIPAddressesInput := &ec2.AssignIpv6AddressesInput{
		NetworkInterfaceId: aws.String(ni.GetInterfaceID()),
		Ipv6AddressCount:   aws.Int64(int64(count)),
	}

	_, err := ec2.New(session).AssignIpv6Addresses(assignPrivateIPAddressesInput)
	return err
}

// GetLockPath returns the path you should use for locks on this interface
func GetLockPath(ni NetworkInterface) string {
	return filepath.Join("interfaces", ni.GetMAC())
}

// GetIPAddressesAsSet converts a function which returns a slice of strings to a set
func GetIPAddressesAsSet(ipAddresses IPFetchFunction) set.Set {
	s := set.NewThreadUnsafeSet()
	for _, ip := range ipAddresses() {
		s.Add(ip)
	}
	return s
}
