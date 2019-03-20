package metadataserver

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/ec2util"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	log "github.com/sirupsen/logrus"
)

const (
	apiProtectInfoFetchTimeout = 5 * time.Second

	// This is the maximum page size
	pageSize = 1000

	// If you want to do API restrict, you have a tag like this on the container's ENI's VPC
	// {
	//   "Value": "12.13.22.104/29,66.77.88.252/30",
	//    "Key": "vpcnat"
	// }
	vpcNatTag = "vpcnat"
)

func getAPIProtectPolicy(parentCtx context.Context, ec2Client *ec2.EC2, vpcID string, ipv4Address, ipv6Address *net.IP) *string {
	ctx, cancel := context.WithTimeout(parentCtx, apiProtectInfoFetchTimeout)
	defer cancel()

	describeVpcsOutput, err := ec2Client.DescribeVpcsWithContext(ctx, &ec2.DescribeVpcsInput{
		VpcIds: aws.StringSlice([]string{vpcID}),
	})

	if err != nil {
		log.WithError(err).Error("Could not describe VPCs")
		return nil
	}

	if len(describeVpcsOutput.Vpcs) != 1 {
		log.Errorf("Did not get one VPC back from describe, instead got %d VPCs", len(describeVpcsOutput.Vpcs))
		return nil
	}

	var nextToken *string
	vpcEndpoints := []*ec2.VpcEndpoint{}
	for {
		describeVpcEndpointsOutput, err := ec2Client.DescribeVpcEndpointsWithContext(ctx, &ec2.DescribeVpcEndpointsInput{
			MaxResults: aws.Int64(pageSize),
			NextToken:  nextToken,
		})
		if err != nil {
			log.WithError(err).Error("Could not fetch VPC endpoints")
			return nil
		}
		vpcEndpoints = append(vpcEndpoints, describeVpcEndpointsOutput.VpcEndpoints...)

		if describeVpcEndpointsOutput.NextToken == nil {
			break
		}
		nextToken = describeVpcEndpointsOutput.NextToken
	}

	return generatePolicy(describeVpcsOutput.Vpcs[0], vpcEndpoints, ipv4Address, ipv6Address)
}

func generatePolicy(vpc *ec2.Vpc, vpcEndpoints []*ec2.VpcEndpoint, ipv4Address *net.IP, ipv6Address *net.IP) *string {
	var (
		_ *net.IP = ipv6Address
		_ *net.IP = ipv4Address
	)
	sourceIPs := []string{}
	if ipv4Address != nil {
		sourceIPs = append(sourceIPs, ipv4Address.String())
	}

	if ipv6Address != nil {
		sourceIPs = append(sourceIPs, ipv6Address.String())
	}

	// Add VPC NAT entries
	vpcTags := ec2util.TagSetToMap(vpc.Tags)
	if vpcNat, ok := vpcTags[vpcNatTag]; ok {
		vpcNATIPAddresses := strings.Split(*vpcNat, ",")
		// we won't validate these
		sourceIPs = append(sourceIPs, vpcNATIPAddresses...)
	} else {
		log.Warning("API Protect not Enabled")
		return nil
	}

	vpcE := []string{}
	for _, vpcEndpoint := range vpcEndpoints {
		vpcE = append(vpcE, *vpcEndpoint.VpcEndpointId)
	}

	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			map[string]interface{}{
				"Effect":   "Deny",
				"Resource": "*",
				"Action":   "*",
				"Condition": map[string]interface{}{
					"NotIpAddress": map[string]interface{}{
						"aws:SourceIP": sourceIPs,
					},
					"ForAnyValue:StringNotEquals": map[string]interface{}{
						"aws:SourceVpc":  *vpc.VpcId,
						"aws:SourceVpce": vpcE,
					},
				},
			},
			map[string]interface{}{
				"Effect":   "Allow",
				"Resource": "*",
				"Action":   "*",
			},
		},
	}

	serializedPolicy, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		log.WithError(err).Warning("Cannot marshal IAM policy")
		return nil
	}

	serializedPolicyString := string(serializedPolicy)
	return &serializedPolicyString
}
