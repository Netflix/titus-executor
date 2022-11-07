package service

import (
	"context"
	"testing"

	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/db/seeds"
	dbutil "github.com/Netflix/titus-executor/vpc/service/db/test"
	"github.com/Netflix/titus-executor/vpc/service/mock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func TestAssignIPV3(t *testing.T) {
	testDB, dbContainer = dbutil.SetupDB(t)
	defer dbutil.ShutdownDB(t, testDB, dbContainer)

	seeds.Execute(testDB, "TrunkEniSeed", "SubnetsSeed", "AvailabilityZoneSeed", "SubnetUsablePrefixSeed", "SubnetCidrReservationV6Seed")

	ctx, cancel := context.WithCancel(context.Background())

	port, err := dbutil.RandomPort()
	require.NoError(t, err)
	addr := ":" + port
	done := make(chan bool)
	ctl := gomock.NewController(t)
	defer ctl.Finish()

	mockSTS := mock.NewMockSTSAPI(ctl)
	mockEC2 := mock.NewMockEC2API(ctl)
	go func() {
		err := runVpcService(ctx, t, addr, mockSTS, mockEC2, testDB, dbContainer)
		if err != nil {
			panic(err)
		}
		done <- true
	}()
	waitForServer(t, addr)

	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
	require.NoError(t, err)
	client := vpcapi.NewTitusAgentVPCServiceClient(conn)

	taskID := "1faff9f0-d92b-4f5b-8bfb-dd035e2b2da5"

	sgA := "sg-mock-a"
	sgB := "sg-mock-b"
	sgC := "sg-mock-c"
	securityGroupIds := []string{
		sgA, sgB, sgC,
	}
	securityGroups := []*ec2.GroupIdentifier{
		{GroupId: &sgA, GroupName: &sgA},
		{GroupId: &sgB, GroupName: &sgB},
		{GroupId: &sgC, GroupName: &sgC},
	}

	ipv4 := &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{
		Ipv4AddressRequested: true,
	}
	ipv6 := &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{
		Ipv6AddressRequested: true,
	}

	subnets := []string{
		"subnet-mock-a",
		"subnet-mock-b",
		"subnet-mock-c",
		"subnet-mock-d",
		"subnet-mock-e",
		"subnet-mock-f",
	}

	accountID := "123456789012"
	region := "us-mock-1"
	elasticAddress := &vpcapi.AssignIPRequestV3_Empty{
		Empty: &empty.Empty{},
	}
	idempotent := false
	burst := true
	jumbo := false
	bandwidth := 750000000
	instanceID := "instance-mock"
	vpcID := "vpc-mock-a"
	subnetID := "subnet-mock-a"

	{
		// Mock GetCallerIdentityWithContext
		{
			mockSTS.EXPECT().
				GetCallerIdentityWithContext(gomock.Any(), gomock.Any()).
				Times(1).
				Return(&sts.GetCallerIdentityOutput{}, nil)
		}

		// Mock DescribeInstancesWithContext
		{
			networkInterfaces := []*ec2.InstanceNetworkInterface{
				{
					Attachment: &ec2.InstanceNetworkInterfaceAttachment{
						AttachmentId:     aws.String("eni-attach-00000000000000001"),
						DeviceIndex:      aws.Int64(0),
						NetworkCardIndex: aws.Int64(0),
						Status:           aws.String("attached"),
					},
					InterfaceType:      aws.String("interface"),
					MacAddress:         aws.String("01:23:45:67:89:aa"),
					NetworkInterfaceId: aws.String("eni-mock-primary"),
					OwnerId:            &accountID,
					Status:             aws.String("in-use"),
					SubnetId:           &subnetID,
					VpcId:              &vpcID,
				},
				{
					Attachment: &ec2.InstanceNetworkInterfaceAttachment{
						AttachmentId:     aws.String("eni-attach-00000000000000002"),
						DeviceIndex:      aws.Int64(1),
						NetworkCardIndex: aws.Int64(0),
						Status:           aws.String("attached"),
					},
					InterfaceType:      aws.String("trunk"),
					MacAddress:         aws.String("01:23:45:67:89:ab"),
					NetworkInterfaceId: aws.String("eni-mock-trunk"),
					OwnerId:            &accountID,
					Status:             aws.String("in-use"),
					SubnetId:           &subnetID,
					VpcId:              &vpcID,
				},
			}
			instance := ec2.Instance{
				InstanceId:        &instanceID,
				InstanceType:      aws.String("r5.metal"),
				NetworkInterfaces: networkInterfaces,
				Placement: &ec2.Placement{
					AvailabilityZone: aws.String("us-mock-1a"),
					GroupName:        aws.String(""),
					Tenancy:          aws.String("default"),
				},
				SubnetId: &subnetID,
				VpcId:    &vpcID,
			}

			input := &ec2.DescribeInstancesInput{InstanceIds: []*string{&instanceID}}
			reservation := &ec2.Reservation{OwnerId: &accountID, Instances: []*ec2.Instance{&instance}}
			output := &ec2.DescribeInstancesOutput{Reservations: []*ec2.Reservation{reservation}}

			mockEC2.EXPECT().
				DescribeInstancesWithContext(gomock.Any(), gomock.Eq(input)).
				Times(1).
				Return(output, nil)
		}

		// Mock DescribeSecurityGroupsWithContext
		{
			securityGroupsIn1 := []*string{aws.String("sg-mock-a")}
			input1 := &ec2.DescribeSecurityGroupsInput{GroupIds: securityGroupsIn1}
			securityGroupsIn2 := []*string{aws.String("sg-mock-b")}
			input2 := &ec2.DescribeSecurityGroupsInput{GroupIds: securityGroupsIn2}
			securityGroupsIn3 := []*string{aws.String("sg-mock-c")}
			input3 := &ec2.DescribeSecurityGroupsInput{GroupIds: securityGroupsIn3}

			securityGroupsOut1 := []*ec2.SecurityGroup{
				{Description: aws.String("sg-mock-a"), GroupId: aws.String("sg-mock-a"), OwnerId: &accountID, VpcId: &vpcID},
			}
			output1 := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: securityGroupsOut1}
			securityGroupsOut2 := []*ec2.SecurityGroup{
				{Description: aws.String("sg-mock-b"), GroupId: aws.String("sg-mock-b"), OwnerId: &accountID, VpcId: &vpcID},
			}
			output2 := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: securityGroupsOut2}
			securityGroupsOut3 := []*ec2.SecurityGroup{
				{Description: aws.String("sg-mock-c"), GroupId: aws.String("sg-mock-c"), OwnerId: &accountID, VpcId: &vpcID},
			}
			output3 := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: securityGroupsOut3}

			gomock.InOrder(
				mockEC2.EXPECT().DescribeSecurityGroupsWithContext(gomock.Any(), gomock.Eq(input1)).Times(1).Return(output1, nil),
				mockEC2.EXPECT().DescribeSecurityGroupsWithContext(gomock.Any(), gomock.Eq(input2)).Times(1).Return(output2, nil),
				mockEC2.EXPECT().DescribeSecurityGroupsWithContext(gomock.Any(), gomock.Eq(input3)).Times(1).Return(output3, nil),
			)
		}

		// Save IPv6 prefixes from CreateNetworkInterface API call, for use in subsequent DescribeNetworkInterfaces API call
		eniIpv6Prefixes := []*ec2.Ipv6PrefixSpecification{}

		// Mock CreateNetworkInterfaceWithContext
		{
			securityGroupPtrs := []*string{}
			for i := range securityGroupIds {
				securityGroupPtrs = append(securityGroupPtrs, &securityGroupIds[i])
			}
			input := mock.MatchCni{
				Eni: &ec2.CreateNetworkInterfaceInput{
					Description: aws.String(vpc.DefaultBranchNetworkInterfaceDescription),
					Groups:      securityGroupPtrs,
					SubnetId:    &subnetID,
				},
			}
			output := &ec2.CreateNetworkInterfaceOutput{
				NetworkInterface: &ec2.NetworkInterface{
					AvailabilityZone:   aws.String("us-mock-1a"),
					Groups:             securityGroups,
					InterfaceType:      aws.String("branch"),
					Ipv6Prefixes:       []*ec2.Ipv6PrefixSpecification{},
					NetworkInterfaceId: aws.String("eni-mock-branch"),
					MacAddress:         aws.String("16:f2:9a:a6:84:69"),
					OwnerId:            &accountID,
					SubnetId:           &subnetID,
					VpcId:              &vpcID,
				},
			}

			mCni := mockEC2.EXPECT().CreateNetworkInterfaceWithContext(gomock.Any(), input, gomock.Any()).Times(1)
			mCni.DoAndReturn(func(ctx context.Context, input *ec2.CreateNetworkInterfaceInput, opts request.Option) (*ec2.CreateNetworkInterfaceOutput, error) {
				// IPv6Prefixes dynamically selected by service code
				output.NetworkInterface.Ipv6Prefixes = []*ec2.Ipv6PrefixSpecification{{Ipv6Prefix: input.Ipv6Prefixes[0].Ipv6Prefix}}
				eniIpv6Prefixes = output.NetworkInterface.Ipv6Prefixes
				return output, nil
			})
		}

		// Mock AssociateTrunkInterface
		{
			input := mock.MatchAti{
				Ati: &ec2.AssociateTrunkInterfaceInput{
					TrunkInterfaceId:  aws.String("eni-mock-trunk"),
					BranchInterfaceId: aws.String("eni-mock-branch"),
				},
			}

			output := &ec2.AssociateTrunkInterfaceOutput{
				InterfaceAssociation: &ec2.TrunkInterfaceAssociation{
					AssociationId:     aws.String("trunk-assoc-12345678"),
					BranchInterfaceId: aws.String("eni-mock-branch"),
					TrunkInterfaceId:  aws.String("eni-mock-trunk"),
				},
			}

			mAti := mockEC2.EXPECT().AssociateTrunkInterfaceWithContext(gomock.Any(), input, gomock.Any()).Times(1)
			mAti.DoAndReturn(func(ctx context.Context, input *ec2.AssociateTrunkInterfaceInput, opts request.Option) (*ec2.AssociateTrunkInterfaceOutput, error) {
				output.ClientToken = input.ClientToken
				output.InterfaceAssociation.VlanId = input.VlanId
				return output, nil
			})
		}

		// Mock DescribeNetworkInterfacesWithContext
		{
			input := &ec2.DescribeNetworkInterfacesInput{
				NetworkInterfaceIds: []*string{
					aws.String("eni-mock-branch"),
				},
			}

			output := &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []*ec2.NetworkInterface{
					{
						AvailabilityZone:   aws.String("us-mock-1a"),
						Groups:             securityGroups,
						InterfaceType:      aws.String("branch"),
						Ipv6Prefixes:       eniIpv6Prefixes,
						NetworkInterfaceId: aws.String("eni-mock-branch"),
						MacAddress:         aws.String("16:f2:9a:a6:84:69"),
						OwnerId:            &accountID,
						PrivateIpAddresses: []*ec2.NetworkInterfacePrivateIpAddress{
							{
								Primary:          aws.Bool(true),
								PrivateIpAddress: aws.String("172.16.0.64"),
							},
						},
						SubnetId: &subnetID,
						VpcId:    &vpcID,
					},
				},
			}

			mockEC2.EXPECT().DescribeNetworkInterfacesWithContext(gomock.Any(), input).Times(1).Return(output, nil)
		}
	}

	instanceIdentity := &vpcapi.InstanceIdentity{
		InstanceID: instanceID,
		AccountID:  accountID,
		Region:     region,
	}

	request := &vpcapi.AssignIPRequestV3{
		TaskId:           taskID,
		SecurityGroupIds: securityGroupIds,
		Ipv6:             ipv6,
		Ipv4:             ipv4,
		Subnets:          subnets,
		InstanceIdentity: instanceIdentity,
		AccountID:        accountID,
		ElasticAddress:   elasticAddress,
		Idempotent:       idempotent,
		Jumbo:            jumbo,
		Burst:            burst,
		Bandwidth:        uint64(bandwidth),
	}
	response, err := client.AssignIPV3(ctx, request)
	require.NoError(t, err)

	expectedResponse := &vpcapi.AssignIPResponseV3{
		Bandwidth: &vpcapi.AssignIPResponseV3_Bandwidth{
			Bandwidth: *aws.Uint64(750000000),
			Burst:     *aws.Uint64(25000000000),
		},
		TrunkNetworkInterface: &vpcapi.NetworkInterface{
			AvailabilityZone: "us-mock-1a",
			MacAddress:       "01:23:45:67:89:ab",
			NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{
				DeviceIndex: *aws.Uint32(1),
			},
			NetworkInterfaceId: "eni-mock-trunk",
			OwnerAccountId:     "123456789012",
			SubnetId:           "subnet-mock-a",
		},
		BranchNetworkInterface: &vpcapi.NetworkInterface{
			AvailabilityZone:   "us-mock-1a",
			MacAddress:         "16:f2:9a:a6:84:69",
			NetworkInterfaceId: "eni-mock-branch",
			OwnerAccountId:     "123456789012",
			SubnetId:           "subnet-mock-a",
			VpcId:              "vpc-mock-a",
		},

		// ClassId selected dynamically by service code
		ClassId: response.ClassId,
		Ipv4Address: &vpcapi.UsableAddress{
			Address: &vpcapi.Address{
				Address: "172.16.0.64",
			},
			PrefixLength: *aws.Uint32(18),
		},
		// Ipv6Address selected dynamically by service code (Ipv6Prefix randomly chosen)
		Ipv6Address: response.Ipv6Address,
		Routes: []*vpcapi.AssignIPResponseV3_Route{
			{
				Destination: "0.0.0.0/0",
				Mtu:         *aws.Uint32(9000),
				Family:      vpcapi.AssignIPResponseV3_Route_IPv4,
			},
			{
				Destination: "::/0",
				Mtu:         *aws.Uint32(9000),
				Family:      vpcapi.AssignIPResponseV3_Route_IPv6,
			},
		},
		// VlanId selected dynamically by service code
		VlanId: response.VlanId,
	}
	assert.Truef(t, proto.Equal(response, expectedResponse), "expected: %s, actual %s", expectedResponse, response)

	cancel()
	<-done
}
