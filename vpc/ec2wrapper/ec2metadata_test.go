package ec2wrapper

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const region = "us-east-1"
const primaryInterfaceMac = "aa:bb:cc:dd:ee:ff"
const secondaryInterfaceMac = "11:22:33:44:55:66"

var errUnknownEndpoint = errors.New("Unknown endpoint")

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

type testInterface struct {
	mac              string
	deviceNumber     int
	interfaceID      string
	ipv4s            []string
	ipv6s            []string
	securityGroupIds []string
}

func (ti *testInterface) getMetadata(p string) (string, error) {
	if p == "device-number" {
		return fmt.Sprintf("%d\n", ti.deviceNumber), nil
	} else if p == "interface-id" {
		return fmt.Sprintf("%s\n", ti.interfaceID), nil
	} else if p == "subnet-id" {
		return "subnet-foo", nil
	} else if p == "security-group-ids" {
		return fmt.Sprintf("%s\n", strings.Join(ti.securityGroupIds, "\n")), nil
	} else if p == "local-ipv4s" {
		return fmt.Sprintf("%s\n", strings.Join(ti.ipv4s, "\n")), nil
	} else if p == "ipv6s" {
		return fmt.Sprintf("%s\n", strings.Join(ti.ipv6s, "\n")), nil
	}

	return "", errUnknownEndpoint
}

type testMetadataServer struct {
	interfaces map[string]*testInterface
}

func (*testMetadataServer) Available() bool {
	return true
}

func (*testMetadataServer) GetDynamicData(p string) (string, error) {
	panic("GetDynamicData not implemented")
}

func (*testMetadataServer) GetInstanceIdentityDocument() (ec2metadata.EC2InstanceIdentityDocument, error) {
	panic("GetInstanceIdentityDocument not implemented")
}

func (tms *testMetadataServer) GetMetadata(p string) (string, error) {
	logrus.WithField("path", p).Info("Handling request")
	path := strings.Trim(p, "/")
	if path == "mac" {
		return fmt.Sprintf("%s\n", primaryInterfaceMac), nil
	} else if path == "network/interfaces/macs" {
		ret := ""
		for mac := range tms.interfaces {
			ret = fmt.Sprintf("%s/\n%s", mac, ret)
		}
		return ret, nil
	} else if strings.HasPrefix(path, "network/interfaces/macs/") {
		subPath := strings.TrimPrefix(path, "network/interfaces/macs/")
		mac := strings.Split(subPath, "/")[0]
		iface := tms.interfaces[mac]
		if iface == nil {
			panic("Received request for unknown interface")
		}
		return iface.getMetadata(strings.TrimPrefix(subPath, mac+"/"))
	}

	return "", errUnknownEndpoint
}

func (*testMetadataServer) GetUserData() (string, error) {
	panic("GetUserData not implemented")
}

func (*testMetadataServer) IAMInfo() (ec2metadata.EC2IAMInfo, error) {
	panic("IAMInfo not implemented")
}

func (*testMetadataServer) Region() (string, error) {
	return region, nil
}

func TestMetadataService(t *testing.T) {

	logger := logrus.New()
	logger.Level = logrus.DebugLevel
	primaryInterface := &testInterface{
		mac:          primaryInterfaceMac,
		deviceNumber: 0,
		interfaceID:  "eni-primary",
		ipv6s:        []string{},
	}
	secondaryInterface := &testInterface{
		mac:          secondaryInterfaceMac,
		ipv4s:        []string{"01.2.3.4", "9.8.1.02"},
		ipv6s:        []string{"2604:5000::bb", "aa:0000:0000::cc"},
		deviceNumber: 1,
		interfaceID:  "eni-secondary",
	}
	tms := &testMetadataServer{
		interfaces: map[string]*testInterface{
			primaryInterfaceMac:   primaryInterface,
			secondaryInterfaceMac: secondaryInterface,
		},
	}

	ec2MetadataClientWrapper := EC2MetadataClientWrapper{
		logger:      logger.WithField("logger", "EC2MetadataClientWrapperTest"),
		ec2metadata: tms,
	}

	mac, err := ec2MetadataClientWrapper.PrimaryInterfaceMac()
	assert.Nil(t, err)
	assert.Equal(t, primaryInterfaceMac, mac)

	interfaces, err := ec2MetadataClientWrapper.Interfaces()
	assert.Nil(t, err)
	assert.Len(t, interfaces, 2)
	assert.Equal(t, []string{"1.2.3.4", "9.8.1.2"}, interfaces[secondaryInterfaceMac].GetIPv4Addresses())
	assert.Equal(t, []string{"2604:5000::bb", "aa::cc"}, interfaces[secondaryInterfaceMac].GetIPv6Addresses())
	assert.Equal(t, []string{}, interfaces[primaryInterfaceMac].GetIPv6Addresses())
}

func TestIPStringToList(t *testing.T) {
	assert.Equal(t, []string{}, ipStringToList(""))
	assert.Equal(t, []string{"1.2.3.4", "4.5.6.8"}, ipStringToList("1.2.3.4\n4.5.6.8\n"))
}
