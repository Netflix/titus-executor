package service

import (
	"context"
	"fmt"
	"regexp"

	"github.com/Netflix/titus-executor/vpc/tracehelpers"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	batchSize = 4
)

var (
	azToRegionRegexp = regexp.MustCompile("[a-z]+-[a-z]+-[0-9]+")
)

func (vpcService *vpcService) AssignIP(ctx context.Context, req *vpcapi.AssignIPRequest) (*vpcapi.AssignIPResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "AssignIP")
	_ = ctx

	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("instance", req.InstanceIdentity.InstanceID),
		trace.BoolAttribute("ipv6AddressRequested", req.Ipv6AddressRequested),
		trace.StringAttribute("securityGroupIds", fmt.Sprint(req.SecurityGroupIds)),
		trace.StringAttribute("allowSecurityGroupChange", fmt.Sprint(req.AllowSecurityGroupChange)),
		trace.Int64Attribute("deviceIdx", int64(req.GetNetworkInterfaceAttachment().DeviceIndex)),
	)

	err := status.Error(codes.Unimplemented, "AssignIP Call is deprecated")
	tracehelpers.SetStatus(err, span)
	return nil, err
}

func (vpcService *vpcService) getTrunkENI(instance *ec2.Instance) *ec2.InstanceNetworkInterface {
	for _, iface := range instance.NetworkInterfaces {
		if aws.StringValue(iface.InterfaceType) == "trunk" {
			return iface
		}
	}
	return nil
}

func (vpcService *vpcService) RefreshIP(ctx context.Context, request *vpcapi.RefreshIPRequest) (*vpcapi.RefreshIPResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "RefreshIP")
	_ = ctx

	defer span.End()

	err := status.Error(codes.Unimplemented, "RefreshIP Call is deprecated")
	tracehelpers.SetStatus(err, span)
	return nil, err
}
