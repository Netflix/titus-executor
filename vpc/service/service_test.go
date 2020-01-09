package service

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/golang/protobuf/ptypes"
	"golang.org/x/crypto/ed25519"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"gotest.tools/assert"
)

func TestService(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "localhost:0")
	assert.NilError(t, err)
	serverErrCh := make(chan error, 1)
	_, privatekey, err := ed25519.GenerateKey(nil)
	assert.NilError(t, err)

	key := vpcapi.PrivateKey{
		Hostname:  "",
		Generated: ptypes.TimestampNow(),
		Key: &vpcapi.PrivateKey_Ed25519Key_{
			Ed25519Key: &vpcapi.PrivateKey_Ed25519Key{
				Rfc8032Key: privatekey.Seed(),
			},
		},
	}

	go func() {
		defer close(serverErrCh)
		serverErr := Run(ctx, &Config{
			Listener:             listener,
			DB:                   nil,
			Key:                  key,
			MaxConcurrentRefresh: 10,
			GCTimeout:            2 * time.Minute,
			ReconcileInterval:    5 * time.Minute,
			RefreshInterval:      30 * time.Second,
			TLSConfig:            nil,
			TitusAgentCACertPool: nil,
		})
		if serverErr != nil && serverErr != context.Canceled {
			serverErrCh <- serverErr
		}
	}()
	t.Run("Healthcheck", func(t2 *testing.T) {
		testHealthcheck(ctx, t2, listener.Addr().String())
	})
	t.Run("HTTPHealthcheck", func(t2 *testing.T) {
		testHTTPHealthcheck(ctx, t2, listener.Addr().String())
	})

	cancel()
	assert.NilError(t, <-serverErrCh)
}

func testHealthcheck(ctx context.Context, t *testing.T, addr string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
	assert.NilError(t, err)
	defer conn.Close()
	healthClient := grpc_health_v1.NewHealthClient(conn)
	healthcheckResponse, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
		Service: "com.netflix.titus.executor.vpc.TitusAgentVPCService",
	})
	assert.NilError(t, err)
	assert.Assert(t, healthcheckResponse.Status == grpc_health_v1.HealthCheckResponse_SERVING)
}

func testHTTPHealthcheck(ctx context.Context, t *testing.T, addr string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rqURL := &url.URL{
		Scheme: "http",
		Host:   addr,
		Path:   "/healthcheck",
	}
	rq, err := http.NewRequest("GET", rqURL.String(), nil)
	assert.NilError(t, err)

	rq = rq.WithContext(ctx)
	response, err := http.DefaultClient.Do(rq)
	assert.NilError(t, err)
	assert.Assert(t, response.StatusCode == http.StatusOK)
	defer response.Body.Close()
	_, err = ioutil.ReadAll(response.Body)
	assert.NilError(t, err)

}
