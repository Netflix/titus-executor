package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Netflix/titus-executor/logger"
	titusTLS "github.com/Netflix/titus-executor/utils/tls"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/config"
	"github.com/golang/protobuf/jsonpb" // nolint: staticcheck
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type Config struct {
	DBURL                 string
	Key                   vpcapi.PrivateKey
	MaxConcurrentRefresh  int64
	MaxConcurrentRequests int
	MaxIdleConnections    int
	MaxOpenConnections    int
	ReconcileInterval     time.Duration
	// How often to collect DB table metrics
	TableMetricsInterval time.Duration

	TLSConfig *tls.Config

	EnabledLongLivedTasks []string
	EnabledTaskLoops      []string

	TrunkNetworkInterfaceDescription  string
	BranchNetworkInterfaceDescription string
	SubnetCIDRReservationDescription  string

	WorkerRole string

	ZipkinURL string

	// This is only used for testing.
	disableRouteCache bool
}

func NewConfig(ctx context.Context, v *viper.Viper) (*Config, error) {
	var signingKey vpcapi.PrivateKey
	signingKeyFile, err := os.Open(v.GetString("signingkey"))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open signing key file")
	}

	err = jsonpb.Unmarshal(signingKeyFile, &signingKey)
	if err != nil {
		signingKeyFile.Close()
		return nil, errors.Wrap(err, "Could not deserialize key")
	}
	signingKeyFile.Close()

	tlsConfig, err := getTLSConfig(ctx, v)
	if err != nil {
		return nil, errors.Wrap(err, "Could not generate TLS Config")
	}

	return &Config{
		DBURL:                 v.GetString(config.DBURLFlagName),
		Key:                   signingKey, // nolint:govet
		MaxConcurrentRefresh:  v.GetInt64(config.MaxConcurrentRefreshFlagName),
		MaxConcurrentRequests: v.GetInt(config.MaxConcurrentRequestsFlagName),
		MaxIdleConnections:    v.GetInt(config.MaxIdleConnectionsFlagName),
		MaxOpenConnections:    v.GetInt(config.MaxOpenConnectionsFlagName),
		ReconcileInterval:     v.GetDuration(config.ReconcileIntervalFlagName),
		TableMetricsInterval:  v.GetDuration(config.TableMetricsIntervalFlagName),
		TLSConfig:             tlsConfig,

		EnabledLongLivedTasks: v.GetStringSlice(config.EnabledLongLivedTasksFlagName),
		EnabledTaskLoops:      v.GetStringSlice(config.EnabledTaskLoopsFlagName),

		TrunkNetworkInterfaceDescription:  v.GetString(config.TrunkENIDescriptionFlagName),
		BranchNetworkInterfaceDescription: v.GetString(config.BranchENIDescriptionFlagName),
		SubnetCIDRReservationDescription:  v.GetString(config.SubnetCIDRReservationFlagName),

		WorkerRole: v.GetString(config.WorkerRoleFlagName),

		ZipkinURL: v.GetString(config.ZipkinURLFlagName),
	}, nil
}

func getTLSConfig(ctx context.Context, v *viper.Viper) (*tls.Config, error) {
	certificateFile := v.GetString(config.SslCertFlagName)
	privateKey := v.GetString(config.SslPrivateKeyFlagName)
	trustedCerts := [1]string{v.GetString(config.SslCAFlagName)}

	if certificateFile == "" && privateKey == "" {
		return nil, nil
	}

	certPool := x509.NewCertPool()
	for _, cert := range trustedCerts {
		logger.G(ctx).WithField("cert", cert).Debug("Loading certificate")
		data, err := ioutil.ReadFile(cert)
		if err != nil {
			return nil, err
		}
		ok := certPool.AppendCertsFromPEM(data)
		if !ok {
			return nil, fmt.Errorf("Cannot load TLS Certificate from %s", cert)
		}
	}

	certLoader := &titusTLS.CachedCertificateLoader{
		CertPath: certificateFile,
		KeyPath:  privateKey,
	}

	tlsConfig := &tls.Config{
		ClientCAs:  certPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader.GetCertificate(tlsConfig.Time)
	}
	return tlsConfig, nil
}
