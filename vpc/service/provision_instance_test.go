package service

import (
	"context"
	"database/sql"
	"testing"

	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	dbutil "github.com/Netflix/titus-executor/vpc/service/db/test"
	"github.com/Netflix/titus-executor/vpc/service/mock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

var testDB *sql.DB
var dbContainer *dbutil.PostgresContainer

func TestProvisionInstanceV3(t *testing.T) {
	testDB, dbContainer = dbutil.SetupDB(t)
	defer dbutil.ShutdownDB(t, testDB, dbContainer)

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

	instanceID := "test-instance"
	subnetID := "subnet-test"
	ownerID := "test-owner"
	trunkEniID := "eni-test"
	macAddress := "01:23:45:67:89:ab"
	az := "us-east-1a"
	vpcID := "vpc-test"
	// Provision an instance for the first time
	{
		// Mock GetCallerIdentityWithContext
		{
			mockSTS.EXPECT().
				GetCallerIdentityWithContext(gomock.Any(), gomock.Any()).
				Times(1). // Should only be called once and then cached
				Return(&sts.GetCallerIdentityOutput{}, nil)
		}

		// Mock DescribeInstancesWithContext
		{
			expectedInput := &ec2.DescribeInstancesInput{InstanceIds: []*string{&instanceID}}
			instance := ec2.Instance{InstanceId: &instanceID, SubnetId: &subnetID}
			reservation := &ec2.Reservation{OwnerId: &ownerID, Instances: []*ec2.Instance{&instance}}
			output := &ec2.DescribeInstancesOutput{Reservations: []*ec2.Reservation{reservation}}

			mockEC2.EXPECT().
				DescribeInstancesWithContext(gomock.Any(), gomock.Eq(expectedInput)).
				Times(1).
				Return(output, nil)
		}

		// Mock CreateNetworkInterfaceWithContext
		{
			expectedInput := &ec2.CreateNetworkInterfaceInput{
				Description:      aws.String(vpc.DefaultTrunkNetworkInterfaceDescription),
				InterfaceType:    aws.String("trunk"),
				Ipv6AddressCount: aws.Int64(0),
				SubnetId:         &subnetID,
			}
			output := &ec2.CreateNetworkInterfaceOutput{
				NetworkInterface: &ec2.NetworkInterface{
					InterfaceType:      aws.String("trunk"),
					VpcId:              &vpcID,
					SubnetId:           &subnetID,
					OwnerId:            &ownerID,
					NetworkInterfaceId: &trunkEniID,
					MacAddress:         &macAddress,
					AvailabilityZone:   &az,
				},
			}
			mockEC2.EXPECT().
				CreateNetworkInterfaceWithContext(gomock.Any(), gomock.Eq(expectedInput)).
				Times(1).
				Return(output, nil)
		}

		// Mock ModifyNetworkInterfaceAttributeWithContext
		{
			expectedInput := &ec2.ModifyNetworkInterfaceAttributeInput{
				SourceDestCheck:    &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
				NetworkInterfaceId: &trunkEniID,
			}
			output := &ec2.ModifyNetworkInterfaceAttributeOutput{}
			mockEC2.EXPECT().
				ModifyNetworkInterfaceAttributeWithContext(gomock.Any(), gomock.Eq(expectedInput)).
				Times(1).
				Return(output, nil)
		}

		// Mock AttachNetworkInterfaceWithContext
		{
			expectedInput := &ec2.AttachNetworkInterfaceInput{
				DeviceIndex:        aws.Int64(1),
				InstanceId:         &instanceID,
				NetworkInterfaceId: &trunkEniID,
			}
			output := &ec2.AttachNetworkInterfaceOutput{}
			mockEC2.EXPECT().
				AttachNetworkInterfaceWithContext(gomock.Any(), gomock.Eq(expectedInput)).
				Times(1).
				Return(output, nil)
		}

		instanceIdentity := &vpcapi.InstanceIdentity{InstanceID: instanceID}
		request := &vpcapi.ProvisionInstanceRequestV3{
			InstanceIdentity: instanceIdentity,
		}
		response, err := client.ProvisionInstanceV3(ctx, request)
		require.NoError(t, err)

		expectedResponse := &vpcapi.ProvisionInstanceResponseV3{
			TrunkNetworkInterface: &vpcapi.NetworkInterface{
				AvailabilityZone:   az,
				MacAddress:         macAddress,
				NetworkInterfaceId: trunkEniID,
				OwnerAccountId:     ownerID,
				VpcId:              vpcID,
			},
		}
		assert.Truef(t, proto.Equal(response, expectedResponse), "expected: %s, actual %s", expectedResponse, response)

		row := testDB.QueryRow("SELECT COUNT(*) from trunk_enis")
		require.Nil(t, row.Err())
		var count uint64
		require.Nil(t, row.Scan(&count))
		assert.Equal(t, uint64(1), count)
		row = testDB.QueryRow("SELECT account_id from trunk_enis where trunk_eni=$1", trunkEniID)
		require.Nil(t, row.Err())
		var accountID string
		require.Nil(t, row.Scan(&accountID))
		assert.Equal(t, ownerID, accountID)
	}

	// Call the same API again. Make sure the API is idempotent.
	{
		// Mock DescribeInstancesWithContext
		{
			expectedInput := &ec2.DescribeInstancesInput{InstanceIds: []*string{&instanceID}}
			networkInterface := ec2.InstanceNetworkInterface{
				OwnerId:            &ownerID,
				VpcId:              &vpcID,
				SubnetId:           &subnetID,
				MacAddress:         &macAddress,
				NetworkInterfaceId: &trunkEniID,
				Attachment:         &ec2.InstanceNetworkInterfaceAttachment{DeviceIndex: aws.Int64(1)},
				InterfaceType:      aws.String("trunk"),
			}
			instance := ec2.Instance{
				InstanceId: &instanceID, SubnetId: &subnetID,
				Placement:         &ec2.Placement{AvailabilityZone: &az},
				NetworkInterfaces: []*ec2.InstanceNetworkInterface{&networkInterface}}
			reservation := &ec2.Reservation{OwnerId: &ownerID, Instances: []*ec2.Instance{&instance}}
			output := &ec2.DescribeInstancesOutput{Reservations: []*ec2.Reservation{reservation}}

			mockEC2.EXPECT().
				DescribeInstancesWithContext(gomock.Any(), gomock.Eq(expectedInput)).
				Times(1).
				Return(output, nil)
		}

		instanceIdentity := &vpcapi.InstanceIdentity{InstanceID: instanceID}
		request := &vpcapi.ProvisionInstanceRequestV3{
			InstanceIdentity: instanceIdentity,
		}
		response, err := client.ProvisionInstanceV3(ctx, request)
		require.NoError(t, err)
		expectedResponse := &vpcapi.ProvisionInstanceResponseV3{
			TrunkNetworkInterface: &vpcapi.NetworkInterface{
				SubnetId:           subnetID,
				AvailabilityZone:   az,
				MacAddress:         macAddress,
				NetworkInterfaceId: trunkEniID,
				OwnerAccountId:     ownerID,
				NetworkInterfaceAttachment: &vpcapi.NetworkInterfaceAttachment{
					DeviceIndex: 1,
				},
			},
		}
		assert.Truef(t, proto.Equal(response, expectedResponse), "expected: %s, actual %s", expectedResponse, response)

		// No more data should be written to DB.
		row := testDB.QueryRow("SELECT COUNT(*) from trunk_enis")
		require.Nil(t, row.Err())
		var count uint64
		require.Nil(t, row.Scan(&count))
		assert.Equal(t, uint64(1), count)
	}

	cancel()
	<-done

	// TODO: More test cases such as:
	// * Concurrent requests
	// * AWS failures
	// * Successfully created interface but fail to attach
}
