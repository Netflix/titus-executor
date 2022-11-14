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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type testData struct {
	accountID        string
	associationID    string
	availabilityZone string
	bandwidth        int64
	branchEniID      string
	burst            bool
	burstBandwidth   int64
	defaultIpv4Route *vpcapi.AssignIPResponseV3_Route
	defaultIpv6Route *vpcapi.AssignIPResponseV3_Route
	elasticAddress   *vpcapi.AssignIPRequestV3_ElasticAdddresses
	idempotent       bool
	instanceID       string
	jumbo            bool
	region           string
	primaryEniID     string
	primaryIPAddress *vpcapi.UsableAddress
	taskID           string
	trunkEniID       string
	securityGroups   []*ec2.GroupIdentifier
	securityGroupIDs []string
	subnetID         string
	subnetIDs        []string
	vpcID            string
}

type networkMode struct {
	ipv4 interface{}
	ipv6 *vpcapi.AssignIPRequestV3_Ipv6AddressRequested
}

func TestAssignIPV3(t *testing.T) {
	testCases := []struct {
		Name   string
		Values networkMode
	}{
		{
			Name: "Ipv4Only",
			Values: networkMode{
				ipv4: &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{Ipv4AddressRequested: true},
			},
		},
		{
			Name: "Ipv6Only",
			Values: networkMode{
				ipv6: &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{Ipv6AddressRequested: true},
			},
		},
		{
			Name: "Ipv6AndIpv4",
			Values: networkMode{
				ipv4: &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{Ipv4AddressRequested: true},
				ipv6: &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{Ipv6AddressRequested: true},
			},
		},
		{
			Name: "Ipv6AndIpv4Fallback",
			Values: networkMode{
				ipv4: &vpcapi.AssignIPRequestV3_TransitionRequested{},
				ipv6: &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{Ipv6AddressRequested: true},
			},
		},
	}

	for _, tc := range testCases {
		t.Logf("TestAssignIPV3 testing %s: %T", tc.Name, tc.Values)
		runTestAssignIPV3(t, tc.Values)
	}
}

func runTestAssignIPV3(t *testing.T, requestType networkMode) {
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

	var sgA, sgB, sgC string = "sg-mock-a", "sg-mock-b", "sg-mock-c"
	var privateIPAddress string = "172.16.0.64"
	td := testData{
		accountID:        "123456789012",
		associationID:    "trunk-assoc-12345678",
		availabilityZone: "us-mock-1a",
		bandwidth:        750000000,
		branchEniID:      "eni-mock-branch",
		burst:            true,
		burstBandwidth:   25000000000,
		defaultIpv4Route: &vpcapi.AssignIPResponseV3_Route{Destination: "0.0.0.0/0", Mtu: *aws.Uint32(9000), Family: vpcapi.AssignIPResponseV3_Route_IPv4},
		defaultIpv6Route: &vpcapi.AssignIPResponseV3_Route{Destination: "::/0", Mtu: *aws.Uint32(9000), Family: vpcapi.AssignIPResponseV3_Route_IPv6},
		elasticAddress:   nil,
		idempotent:       false,
		instanceID:       "instance-mock",
		jumbo:            false,
		primaryEniID:     "eni-mock-primary",
		primaryIPAddress: &vpcapi.UsableAddress{Address: &vpcapi.Address{Address: privateIPAddress}, PrefixLength: *aws.Uint32(18)},
		region:           "us-mock-1",
		taskID:           "1faff9f0-d92b-4f5b-8bfb-dd035e2b2da5",
		trunkEniID:       "eni-mock-trunk",
		securityGroups:   []*ec2.GroupIdentifier{{GroupId: &sgA, GroupName: &sgA}, {GroupId: &sgB, GroupName: &sgB}, {GroupId: &sgC, GroupName: &sgC}},
		securityGroupIDs: []string{sgA, sgB, sgC},
		subnetID:         "subnet-mock-a",
		subnetIDs:        []string{"subnet-mock-a", "subnet-mock-b", "subnet-mock-c", "subnet-mock-d", "subnet-mock-e", "subnet-mock-f"},
		vpcID:            "vpc-mock-a",
	}

	primaryEni := ec2.InstanceNetworkInterface{
		Attachment: &ec2.InstanceNetworkInterfaceAttachment{
			AttachmentId:     aws.String("eni-attach-00000000000000001"),
			DeviceIndex:      aws.Int64(0),
			NetworkCardIndex: aws.Int64(0),
			Status:           aws.String("attached"),
		},
		InterfaceType:      aws.String("interface"),
		MacAddress:         aws.String("01:23:45:67:89:aa"),
		NetworkInterfaceId: &td.primaryEniID,
		OwnerId:            &td.accountID,
		Status:             aws.String("in-use"),
		SubnetId:           &td.subnetID,
		VpcId:              &td.vpcID,
	}
	trunkEni := ec2.InstanceNetworkInterface{
		Attachment: &ec2.InstanceNetworkInterfaceAttachment{
			AttachmentId:     aws.String("eni-attach-00000000000000002"),
			DeviceIndex:      aws.Int64(1),
			NetworkCardIndex: aws.Int64(0),
			Status:           aws.String("attached"),
		},
		InterfaceType:      aws.String("trunk"),
		MacAddress:         aws.String("01:23:45:67:89:ab"),
		NetworkInterfaceId: &td.trunkEniID,
		OwnerId:            &td.accountID,
		Status:             aws.String("in-use"),
		SubnetId:           &td.subnetID,
		VpcId:              &td.vpcID,
	}
	branchEni := ec2.NetworkInterface{
		AvailabilityZone:   &td.availabilityZone,
		Groups:             td.securityGroups,
		InterfaceType:      aws.String("branch"),
		Ipv6Prefixes:       []*ec2.Ipv6PrefixSpecification{},
		NetworkInterfaceId: &td.branchEniID,
		MacAddress:         aws.String("16:f2:9a:a6:84:69"),
		OwnerId:            &td.accountID,
		SubnetId:           &td.subnetID,
		VpcId:              &td.vpcID,
	}
	instance := ec2.Instance{
		InstanceId:        &td.instanceID,
		InstanceType:      aws.String("r5.metal"),
		NetworkInterfaces: []*ec2.InstanceNetworkInterface{&primaryEni, &trunkEni},
		Placement: &ec2.Placement{
			AvailabilityZone: &td.availabilityZone,
			GroupName:        aws.String(""),
			Tenancy:          aws.String("default"),
		},
		SubnetId: &td.subnetID,
		VpcId:    &td.vpcID,
	}
	expectedResponse := &vpcapi.AssignIPResponseV3{
		Bandwidth: &vpcapi.AssignIPResponseV3_Bandwidth{
			Bandwidth: uint64(td.bandwidth),
			Burst:     uint64(td.burstBandwidth),
		},
		TrunkNetworkInterface: &vpcapi.NetworkInterface{
			AvailabilityZone:           td.availabilityZone,
			MacAddress:                 *trunkEni.MacAddress,
			NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{DeviceIndex: uint32(*trunkEni.Attachment.DeviceIndex)},
			NetworkInterfaceId:         td.trunkEniID,
			OwnerAccountId:             *trunkEni.OwnerId,
			SubnetId:                   *trunkEni.SubnetId,
		},
		BranchNetworkInterface: &vpcapi.NetworkInterface{
			AvailabilityZone:   *branchEni.AvailabilityZone,
			MacAddress:         *branchEni.MacAddress,
			NetworkInterfaceId: td.branchEniID,
			OwnerAccountId:     *branchEni.OwnerId,
			SubnetId:           *branchEni.SubnetId,
			VpcId:              *branchEni.VpcId,
		},
		Routes: []*vpcapi.AssignIPResponseV3_Route{td.defaultIpv4Route, td.defaultIpv6Route},
	}

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
			input := &ec2.DescribeInstancesInput{InstanceIds: []*string{&td.instanceID}}
			reservation := &ec2.Reservation{OwnerId: &td.accountID, Instances: []*ec2.Instance{&instance}}
			output := &ec2.DescribeInstancesOutput{Reservations: []*ec2.Reservation{reservation}}

			mockEC2.EXPECT().
				DescribeInstancesWithContext(gomock.Any(), gomock.Eq(input)).
				Times(1).
				Return(output, nil)
		}

		// Mock DescribeSecurityGroupsWithContext
		{
			input1 := &ec2.DescribeSecurityGroupsInput{GroupIds: []*string{&td.securityGroupIDs[0]}}
			input2 := &ec2.DescribeSecurityGroupsInput{GroupIds: []*string{&td.securityGroupIDs[1]}}
			input3 := &ec2.DescribeSecurityGroupsInput{GroupIds: []*string{&td.securityGroupIDs[2]}}

			output1 := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []*ec2.SecurityGroup{
				{Description: &td.securityGroupIDs[0], GroupId: &td.securityGroupIDs[0], OwnerId: &td.accountID, VpcId: &td.vpcID}},
			}
			output2 := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []*ec2.SecurityGroup{
				{Description: &td.securityGroupIDs[1], GroupId: &td.securityGroupIDs[1], OwnerId: &td.accountID, VpcId: &td.vpcID}},
			}
			output3 := &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []*ec2.SecurityGroup{
				{Description: &td.securityGroupIDs[2], GroupId: &td.securityGroupIDs[2], OwnerId: &td.accountID, VpcId: &td.vpcID}},
			}

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
			for i := range td.securityGroupIDs {
				securityGroupPtrs = append(securityGroupPtrs, &td.securityGroupIDs[i])
			}
			input := mock.MatchCni{
				Eni: &ec2.CreateNetworkInterfaceInput{Description: aws.String(vpc.DefaultBranchNetworkInterfaceDescription), Groups: securityGroupPtrs, SubnetId: &td.subnetID},
			}
			output := &ec2.CreateNetworkInterfaceOutput{NetworkInterface: &branchEni}

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
				Ati: &ec2.AssociateTrunkInterfaceInput{TrunkInterfaceId: &td.trunkEniID, BranchInterfaceId: &td.branchEniID},
			}

			output := &ec2.AssociateTrunkInterfaceOutput{
				InterfaceAssociation: &ec2.TrunkInterfaceAssociation{
					AssociationId:     &td.associationID,
					BranchInterfaceId: &td.branchEniID,
					TrunkInterfaceId:  &td.trunkEniID,
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
			input := &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []*string{aws.String("eni-mock-branch")}}

			branchEni.Ipv6Prefixes = eniIpv6Prefixes
			branchEni.PrivateIpAddresses = []*ec2.NetworkInterfacePrivateIpAddress{{Primary: aws.Bool(true), PrivateIpAddress: &privateIPAddress}}
			output := &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []*ec2.NetworkInterface{&branchEni}}

			mockEC2.EXPECT().DescribeNetworkInterfacesWithContext(gomock.Any(), input).Times(1).Return(output, nil)
		}
	}

	instanceIdentity := &vpcapi.InstanceIdentity{
		InstanceID: td.instanceID,
		AccountID:  td.accountID,
		Region:     td.region,
	}

	request := &vpcapi.AssignIPRequestV3{
		AccountID:        td.accountID,
		Bandwidth:        uint64(td.bandwidth),
		Burst:            td.burst,
		ElasticAddress:   td.elasticAddress,
		InstanceIdentity: instanceIdentity,
		Idempotent:       td.idempotent,
		Ipv6:             requestType.ipv6,
		Jumbo:            td.jumbo,
		SecurityGroupIds: td.securityGroupIDs,
		Subnets:          td.subnetIDs,
		TaskId:           td.taskID,
	}

	switch v := requestType.ipv4.(type) {
	case *vpcapi.AssignIPRequestV3_Ipv4AddressRequested:
		request.Ipv4 = requestType.ipv4.(*vpcapi.AssignIPRequestV3_Ipv4AddressRequested)
	case *vpcapi.AssignIPRequestV3_TransitionRequested:
		request.Ipv4 = requestType.ipv4.(*vpcapi.AssignIPRequestV3_TransitionRequested)
	case nil:
	default:
		t.Fatalf("Unknown Ipv4AddressRequest type: %T", v)
	}

	response, err := client.AssignIPV3(ctx, request)
	require.NoError(t, err)

	switch (requestType.ipv4).(type) {
	case *vpcapi.AssignIPRequestV3_Ipv4AddressRequested:
		expectedResponse.Ipv4Address = td.primaryIPAddress
	case *vpcapi.AssignIPRequestV3_TransitionRequested:
		expectedResponse.Ipv4Address = nil
		expectedResponse.TransitionAssignment = &vpcapi.AssignIPResponseV3_TransitionAssignment{
			// AssignmentId is selected dynamically by service code (UUID)
			AssignmentId: response.TransitionAssignment.AssignmentId,
			Routes:       []*vpcapi.AssignIPResponseV3_Route{td.defaultIpv4Route, td.defaultIpv6Route},
			Ipv4Address:  td.primaryIPAddress,
		}
	}

	// ClassId, Ipv6Address (Ipv6Prefix randomly chosen), and VlanId fields are selected dynamically by service code
	expectedResponse.ClassId = response.ClassId
	expectedResponse.Ipv6Address = response.Ipv6Address
	expectedResponse.VlanId = response.VlanId

	assert.Truef(t, proto.Equal(response, expectedResponse), "expected: %s, actual %s", expectedResponse, response)

	cancel()
	<-done
}
