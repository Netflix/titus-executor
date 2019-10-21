package service

import (
	"context"
	x509 "crypto/x509"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"

	"github.com/Netflix/titus-executor/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func populateAuthInfo(l logrus.FieldLogger, info credentials.AuthInfo) logrus.FieldLogger {
	authType := info.AuthType()

	l = l.WithField("authtype", authType)
	switch t := info.(type) {
	case credentials.TLSInfo:
		sv := t.GetSecurityValue().(*credentials.TLSChannelzSecurityValue)
		l = l.WithField("standardName", sv.StandardName)
		if sv.RemoteCertificate != nil {
			cert, err := x509.ParseCertificate(sv.RemoteCertificate)
			if err != nil {
				panic(err)
			}
			l = l.WithField("DNSNames", cert.DNSNames)
			l = l.WithField("IPAddresses", cert.IPAddresses)
			l = l.WithField("EmailAddresses", cert.EmailAddresses)
			l = l.WithField("IPAddresses", cert.IPAddresses)
			l = l.WithField("URIs", cert.URIs)
			for _, ext := range cert.Extensions {
				l = l.WithField("extension."+ext.Id.String(), string(ext.Value))
			}
			for _, ext := range cert.ExtraExtensions {
				l = l.WithField("extraExtension."+ext.Id.String(), string(ext.Value))
			}
		}
		l = l.WithField("peerCertificates", t.State.PeerCertificates)
	}
	return l
}

func (*vpcService) authFunc(ctx context.Context) (context.Context, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Internal, "Could not retrieve peer from context")
	}
	l := logger.G(ctx)
	if peer.AuthInfo != nil {
		populateAuthInfo(l, peer.AuthInfo).Debug("Authenticating peers via authFunc")
	} else {
		l.Debug("not authenticating peers via AuthFuncOverride")

	}
	return ctx, nil
}
