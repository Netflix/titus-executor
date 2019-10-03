package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"go.opencensus.io/plugin/ocgrpc"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	pkgviper "github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func addSharedFlags(flags *pflag.FlagSet) {
	flags.String(stateDirFlagName, stateDirDefaultValue, "Where do we put the state")
	flags.String(serviceAddrFlagName, serviceAddrDefaultValue, "VPC service address")
}

func getSharedValues(ctx context.Context, v *pkgviper.Viper) (*fslocker.FSLocker, *grpc.ClientConn, error) {
	serviceAddr := v.GetString(serviceAddrFlagName)

	keepaliveParams := keepalive.ClientParameters{
		Time:                time.Minute,
		PermitWithoutStream: true,
	}
	entry := logger.G(ctx).(*logrus.Logger).WithField("origin", "grpc")

	entry.WithField("serviceAddr", serviceAddr).Debug("Initializing client")
	grpc_logrus.ReplaceGrpcLogger(entry)
	conn, err := grpc.DialContext(ctx, serviceAddr,
		grpc.WithStatsHandler(&ocgrpc.ClientHandler{}),
		grpc.WithInsecure(),
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
		return nil, nil, err
	}

	stateDir := v.GetString(stateDirFlagName)
	fslockerDir := filepath.Join(stateDir, "fslocker")
	if err := os.MkdirAll(fslockerDir, 0700); err != nil {
		return nil, nil, err
	}
	locker, err := fslocker.NewFSLocker(fslockerDir)
	if err != nil {
		return nil, nil, err
	}

	return locker, conn, nil
}
