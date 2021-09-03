package main

import (
	"context"
	"crypto/tls"
	x509 "crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	pkgviper "github.com/spf13/viper"
	"go.opencensus.io/plugin/ocgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func addSharedFlags(flags *pflag.FlagSet) {
	flags.String(stateDirFlagName, stateDirDefaultValue, "Where do we put the state")
	flags.String(serviceAddrFlagName, serviceAddrDefaultValue, "VPC service address")
	flags.String(generationFlagName, generationDefaultValue, "Generation of VPC Tool to use, specify v1, or v2")
	flags.String(sslCAFlagName, "", "SSL CA")
	flags.String(sslKeyFlagName, "", "SSL Key")
	flags.String(sslCertFlagName, "", "SSL Cert")
	flags.String(transitionNSDirFlagName, "/run/transition", "Directory to mount transition namespaces into")

}

func getSecurityConfiguration(ctx context.Context, v *pkgviper.Viper) (grpc.DialOption, error) {
	sslCA := v.GetString(sslCAFlagName)
	sslKey := v.GetString(sslKeyFlagName)
	sslCert := v.GetString(sslCertFlagName)
	if sslCA == "" || sslKey == "" || sslCert == "" {
		return grpc.WithInsecure(), nil
	}
	certpool, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.Wrap(err, "Cannot load system cert pool")
	}
	data, err := ioutil.ReadFile(sslCA)
	if err != nil {
		return nil, errors.Wrapf(err, "Cannot read CA file %s", sslCA)
	}
	if ok := certpool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("Cannot load cert data from file %s", sslCA)
	}
	tlsConfig := &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(sslCert, sslKey)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
		RootCAs:    certpool,
		MinVersion: tls.VersionTLS12,
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), nil
}

func getConnection(ctx context.Context, v *pkgviper.Viper) (*grpc.ClientConn, error) {
	serviceAddr := v.GetString(serviceAddrFlagName)

	keepaliveParams := keepalive.ClientParameters{
		Time:                2 * time.Minute,
		Timeout:             5 * time.Minute,
		PermitWithoutStream: true,
	}
	entry := logger.G(ctx).(*logrus.Logger).WithField("origin", "grpc")

	entry.WithField("serviceAddr", serviceAddr).Debug("Initializing client")
	grpc_logrus.ReplaceGrpcLogger(entry)
	securityDialOption, err := getSecurityConfiguration(ctx, v)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot configure ")
	}
	conn, err := grpc.DialContext(ctx, serviceAddr,
		grpc.WithStatsHandler(&ocgrpc.ClientHandler{}),
		securityDialOption,
		grpc.WithKeepaliveParams(keepaliveParams),
		grpc.WithUnaryInterceptor(
			grpc_middleware.ChainUnaryClient(
				grpc_logrus.UnaryClientInterceptor(entry),
			)),
		grpc.WithStreamInterceptor(
			grpc_middleware.ChainStreamClient(
				grpc_logrus.StreamClientInterceptor(entry),
			)))
	if err != nil {
		return nil, fmt.Errorf("Unable to create grpc conneciton: %w", err)
	}

	return conn, nil
}

func getLocker(ctx context.Context, v *pkgviper.Viper) (*fslocker.FSLocker, error) {
	stateDir := v.GetString(stateDirFlagName)
	fslockerDir := filepath.Join(stateDir, "fslocker")
	if err := os.MkdirAll(fslockerDir, 0700); err != nil {
		return nil, err
	}
	locker, err := fslocker.NewFSLocker(fslockerDir)
	if err != nil {
		return nil, err
	}

	return locker, nil
}
