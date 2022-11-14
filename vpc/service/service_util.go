package service

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	dbutil "github.com/Netflix/titus-executor/vpc/service/db/test"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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
	mockSTS stsiface.STSAPI, mockEC2 ec2iface.EC2API,
	testDB *sql.DB, dbContainer *dbutil.PostgresContainer) error {

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
		MaxConcurrentRequests: 190,

		BranchNetworkInterfaceDescription: vpc.DefaultBranchNetworkInterfaceDescription,
		TrunkNetworkInterfaceDescription:  vpc.DefaultTrunkNetworkInterfaceDescription,
		SubnetCIDRReservationDescription:  vpc.DefaultSubnetCIDRReservationDescription,

		disableRouteCache: true,
	}

	vpcService, err := newVpcService(ctx, vpcServiceConfig)
	require.NoError(t, err)

	vpcService.dynamicConfig = NewDynamicConfig()
	vpcService.dynamicConfig.configs["ENABLE_RANDOM_BRANCH_ENI"] = "FALSE"

	vpcService.ec2.NewSts = func(p client.ConfigProvider, cfgs ...*aws.Config) stsiface.STSAPI {
		return mockSTS
	}
	vpcService.ec2.NewEC2 = func(p client.ConfigProvider, cfgs ...*aws.Config) ec2iface.EC2API {
		return mockEC2
	}

	err = vpcService.run(ctx, addr)
	require.NoError(t, err)

	return nil
}
