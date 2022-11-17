package service

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/db"
	db_test "github.com/Netflix/titus-executor/vpc/service/db/test"
	"github.com/Netflix/titus-executor/vpc/service/mock"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testDB *sql.DB
var dbContainer *db_test.PostgresContainer

const (
	trunkENIDescription  = "test-trunk-eni-description"
	branchENIDescription = "test-branch-eni-description"
)

func skipIfNoDocker(t *testing.T) {
	c, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		t.Skip("Skip because no docker daemon is running")
	}
	defer c.Close()
}

func setupDB(t *testing.T) {
	skipIfNoDocker(t)
	ctx := context.Background()
	var err error
	dbContainer, err = db_test.StartPostgresContainer(ctx, "e2e_test_db")
	if err != nil {
		t.Fatalf("failed to start postgress container: %s", err)
	}
	testDB, err = dbContainer.Connect(ctx)
	if err != nil {
		t.Skipf("failed to connect to test DB: %s", err)
	}
	// Set up tables
	err = db.MigrateTo(ctx, testDB, 40, false)
	if err != nil {
		t.Fatalf("failed to set up tables: %s", err)
	}
}

func shutdownDB(t *testing.T) {
	err := dbContainer.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("failed to clean up container: %s", err)
	}
	testDB.Close()
}

func waitForServer(t *testing.T, addr string) {
	done := make(chan bool)
	go func() {
		for {
			ctx := context.Background()
			conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			defer conn.Close()
			healthClient := grpc_health_v1.NewHealthClient(conn)
			healthcheckResponse, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
				Service: "com.netflix.titus.executor.vpc.TitusAgentVPCService",
			})

			if err == nil && healthcheckResponse.Status == grpc_health_v1.HealthCheckResponse_SERVING {
				done <- true
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case <-done:
		t.Logf("GPRC server is running and healthy")
	case <-time.After(2 * time.Second):
		t.Fatalf("GRPC server is still not healthy after 2s")
	}
}

func runVpcService(ctx context.Context, t *testing.T, addr string,
	mockSTS stsiface.STSAPI, mockEC2 ec2iface.EC2API) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	key := vpcapi.PrivateKey{
		Hostname:  "",
		Generated: timestamppb.Now(),
		Key: &vpcapi.PrivateKey_Ed25519Key_{
			Ed25519Key: &vpcapi.PrivateKey_Ed25519Key{
				Rfc8032Key: privateKey.Seed(),
			},
		},
	}

	// Insert public key
	_, err = testDB.ExecContext(ctx,
		"INSERT INTO trusted_public_keys(hostname, created_at, key, keytype) VALUES('test-host', now(), $1, 'ed25519')",
		publicKey)
	require.NoError(t, err)

	vpcServiceConfig := &Config{
		DBURL:                 dbContainer.DBURL(),
		Key:                   key, // nolint:govet
		ReconcileInterval:     5 * time.Minute,
		TLSConfig:             nil,
		EnabledTaskLoops:      []string{},
		EnabledLongLivedTasks: []string{},
		WorkerRole:            "testWorkerRole",

		TrunkNetworkInterfaceDescription:  trunkENIDescription,
		BranchNetworkInterfaceDescription: branchENIDescription,

		disableRouteCache: true,
	}
	vpcService, err := newVpcService(ctx, vpcServiceConfig)
	require.NoError(t, err)

	vpcService.ec2.NewSts = func(p client.ConfigProvider, cfgs ...*aws.Config) stsiface.STSAPI {
		return mockSTS
	}
	vpcService.ec2.NewEC2 = func(p client.ConfigProvider, cfgs ...*aws.Config) ec2iface.EC2API {
		return mockEC2
	}

	err = vpcService.run(ctx, addr)
	require.NoError(t, err)
}

func TestProvisionInstanceV3(t *testing.T) {
	setupDB(t)
	defer shutdownDB(t)

	ctx, cancel := context.WithCancel(context.Background())

	port, err := db_test.RandomPort()
	require.NoError(t, err)
	addr := ":" + port
	done := make(chan bool)
	ctl := gomock.NewController(t)
	defer ctl.Finish()

	mockSTS := mock.NewMockSTSAPI(ctl)
	mockEC2 := mock.NewMockEC2API(ctl)
	go func() {
		runVpcService(ctx, t, addr, mockSTS, mockEC2)
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
				Description:      aws.String(trunkENIDescription),
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
