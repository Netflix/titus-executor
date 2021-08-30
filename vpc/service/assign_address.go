package service

import (
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

const (
	batchSize = 4
)

var (
	azToRegionRegexp = regexp.MustCompile("[a-z]+-[a-z]+-[0-9]+")
)

func (vpcService *vpcService) getTrunkENI(instance *ec2.Instance) *ec2.InstanceNetworkInterface {
	for _, iface := range instance.NetworkInterfaces {
		if aws.StringValue(iface.InterfaceType) == "trunk" {
			return iface
		}
	}
	return nil
}
