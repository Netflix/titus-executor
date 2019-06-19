package service

import (
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
)

type vpcService struct {
	ec2 ec2wrapper.EC2SessionManager
}
