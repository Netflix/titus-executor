package metadataserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/logging"
	"github.com/Netflix/titus-executor/metadataserver/metrics"
	"github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/gorilla/mux"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_logrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/plugin/ocgrpc"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

// Derived from big data portal reports
const defaultMacAddress = "00:00:00:00:00:00"
const notFoundBody = `<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>404 - Not Found</title>
 </head>
 <body>
  <h1>404 - Not Found</h1>
 </body>
</html>`

// A sentinel role used under test
const FakeARNRole = "arn:aws:iam::0:role/RealRole"

var whitelist = sets.NewString(
	"/latest/meta-data",
	"/latest/meta-data/network/interfaces/macs/null/vpc-id",
	"/latest/meta-data/network/interfaces/macs/00:00:00:00:00:00/vpc-id",
	"/latest/dynamic/instance-identity",
	"/latest/user-data",
	"/latest/meta-data/placement",
	"/latest/meta-data/iam",
)

/*
 * The processing pipeline should go ->
 * 0. Setup / wrap logging infrastructure
 * 1. Locally handled routes
 * 2. Check the whitelist
 * 3. Proxy!
 */

// MetadataServer implements http.Handler, it can be passed to a real, or fake HTTP server for testing
type MetadataServer struct {
	httpClient  *http.Client
	internalMux *mux.Router
	iamProxy    *iamProxy
	/*
		The below stuff could be called *instance specific metadata*
		I'd rather not break it into owns struct
	*/
	titusTaskInstanceID string
	ipv4Address         net.IP
	publicIpv4Address   net.IP
	ipv6Address         *net.IP
	accountID           string
	launched            time.Time
	pod                 *corev1.Pod
	containerInfo       *titus.ContainerInfo
	signer              *identity.Signer
	// Need to hold `signLock` while accessing `signer`
	signLock                  sync.RWMutex
	tokenRequired             bool
	tokenKey                  []byte
	xForwardedForBlockingMode bool
	ec2metadatasvc            *ec2metadata.EC2Metadata
	// Dynamically resolved
	sf                 singleflight.Group
	availabilityZone   string
	availabilityZoneID string
	region             string
}

func dumpRoutes(r *mux.Router) {
	err := r.Walk(
		func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			pathTemplate, err := route.GetPathTemplate()
			if err != nil {
				panic(err)
			}
			log.WithFields(map[string]interface{}{
				"routeName":         route.GetName(),
				"routePathTemplate": pathTemplate,
			}).Debug("Gorilla Route")
			return nil
		})
	_ = err
}

// NewMetaDataServer which can be used as an HTTP server's handler
func NewMetaDataServer(ctx context.Context, config types.MetadataServerConfiguration) (*MetadataServer, error) {
	awsConfig := aws.NewConfig()
	awsConfig.Endpoint = aws.String(config.BackingMetadataServer.String())
	awsSession, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("Could not setup AWS Session: %w", err)
	}
	svc := ec2metadata.New(awsSession)

	ms := &MetadataServer{
		httpClient:                &http.Client{},
		internalMux:               mux.NewRouter(),
		titusTaskInstanceID:       config.TitusTaskInstanceID,
		ipv4Address:               config.Ipv4Address,
		publicIpv4Address:         config.PublicIpv4Address,
		ipv6Address:               config.Ipv6Address,
		accountID:                 config.NetflixAccountID,
		launched:                  time.Now(),
		ec2metadatasvc:            svc,
		pod:                       config.Pod,
		containerInfo:             config.ContainerInfo,
		signer:                    config.Signer,
		tokenRequired:             config.RequireToken,
		xForwardedForBlockingMode: config.XFordwardedForBlockingMode,

		region:             config.Region,
		availabilityZone:   config.AvailabilityZone,
		availabilityZoneID: config.AvailabilityZoneID,
	}

	var conn *grpc.ClientConn
	if config.IAMService != "" {
		certpool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("Cannot load system cert pool: %w", err)
		}
		data, err := ioutil.ReadFile(config.SSLCA)
		if err != nil {
			return nil, fmt.Errorf("Cannot read CA file %q: %w", config.SSLCA, err)
		}
		if ok := certpool.AppendCertsFromPEM(data); !ok {
			return nil, fmt.Errorf("Cannot load cert data from file %s", config.SSLCA)
		}
		tlsConfig := &tls.Config{
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				cert, err := tls.LoadX509KeyPair(config.SSLCert, config.SSLKey)
				if err != nil {
					return nil, err
				}
				return &cert, nil
			},
			RootCAs:            certpool,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // nolint:gosec
			VerifyPeerCertificate: func(certificates [][]byte, _ [][]*x509.Certificate) error {
				certs := make([]*x509.Certificate, len(certificates))
				for i, asn1Data := range certificates {
					cert, err := x509.ParseCertificate(asn1Data)
					if err != nil {
						return errors.New("failed to parse certificate from server: " + err.Error())
					}
					certs[i] = cert
				}

				// Leave DNSName empty to skip hostname verification.
				opts := x509.VerifyOptions{
					Roots:         certpool,
					Intermediates: x509.NewCertPool(),
				}
				// Skip the first cert because it's the leaf. All others
				// are intermediates.
				for _, cert := range certs[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := certs[0].Verify(opts)
				return err
			},
		}
		entry := logger.G(ctx).(*log.Logger).WithField("origin", "grpc")

		entry.Debug("Initializing client")

		conn, err = grpc.DialContext(ctx, config.IAMService,
			grpc.WithStatsHandler(&ocgrpc.ClientHandler{}),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
			grpc.WithUnaryInterceptor(
				grpc_middleware.ChainUnaryClient(
					grpc_logrus.UnaryClientInterceptor(entry),
				)),
			grpc.WithStreamInterceptor(
				grpc_middleware.ChainStreamClient(
					grpc_logrus.StreamClientInterceptor(entry),
				)))
		if err != nil {
			return nil, fmt.Errorf("Cannot setup GRPC connection: %w", err)
		}
	}
	ms.tokenKey = []byte(config.TokenKey)

	// Create the IAM proxy - we'll attach routes to it for the different versions when we install handlers below
	if config.IAMARN != FakeARNRole {
		ms.iamProxy = newIamProxy(ctx, config, conn)
	}

	/* IMDS routes */
	ms.internalMux.Use(ms.serverHeader)

	// v2
	latestVersionGenToken := ms.internalMux.PathPrefix("/latest/api/token").Subrouter()
	latestVersionGenToken.HandleFunc("", ms.createAuthTokenHandler).Methods(http.MethodPut)

	latestVersion := ms.internalMux.PathPrefix("/latest").Subrouter()
	latestVersion.Use(ms.authenticate)
	ms.installIMDSCommonHandlers(ctx, latestVersion, config)

	// v1
	v1Version := ms.internalMux.PathPrefix("/1.0").Subrouter()
	ms.installIMDSCommonHandlers(ctx, v1Version, config)

	/* Titus routes */
	titusRouter := ms.internalMux.PathPrefix("/nflx/v1").Subrouter()
	ms.installTitusHandlers(titusRouter, config)

	/* Dump debug routes if anyone cares */
	dumpRoutes(ms.internalMux)

	return ms, nil
}

func (ms *MetadataServer) serverHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Server", "EC2ws")
		next.ServeHTTP(w, r)
	})
}

func (ms *MetadataServer) installTitusHandlers(router *mux.Router, config types.MetadataServerConfiguration) {
	if config.Signer != nil {
		router.Headers("Accept", "application/json").Path("/task-identity").HandlerFunc(ms.taskIdentityJSON)
		router.HandleFunc("/task-identity", ms.taskIdentity)
		router.HandleFunc("/task-pod-identity", ms.taskPodIdentity)
	}
}

func (ms *MetadataServer) installIMDSCommonHandlers(ctx context.Context, router *mux.Router, config types.MetadataServerConfiguration) {
	router.HandleFunc("/ping", ms.ping)

	metaData := router.PathPrefix("/meta-data").Subrouter()
	metaData.HandleFunc("/mac", ms.macAddr)
	metaData.HandleFunc("/instance-id", ms.instanceID)
	metaData.HandleFunc("/local-ipv4", ms.localIPV4)
	metaData.HandleFunc("/public-ipv4", ms.publicIPV4)
	metaData.HandleFunc("/local-hostname", ms.localHostname)
	metaData.HandleFunc("/hostname", ms.hostname)
	metaData.HandleFunc("/public-hostname", ms.publicHostname)
	metaData.HandleFunc("/placement/region", ms.placementRegion)
	metaData.HandleFunc("/placement/availability-zone", ms.placementAZ)
	metaData.HandleFunc("/placement/availability-zone-id", ms.placementAZID)

	/* Specifically return 404 on these endpoints */
	metaData.Handle("/ami-id", http.NotFoundHandler())
	metaData.Handle("/instance-type", http.NotFoundHandler())

	/* IAM Stuffs */
	ms.iamProxy.AttachRoutes(metaData.PathPrefix("/iam").Subrouter())

	/*
		Instance identity document
		We do not handle the following paths:
		* pkcs7
		* rsa2048
		* signature
	*/
	router.Path("/dynamic/instance-identity/document").HandlerFunc(ms.instanceIdentityDocument)

	/* Catch All */
	router.PathPrefix("/").Handler(newProxy(config.BackingMetadataServer))
}

func (ms *MetadataServer) macAddr(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.macAddr.count")
	if _, err := fmt.Fprint(w, defaultMacAddress); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) instanceID(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.instanceId.count")
	if _, err := fmt.Fprint(w, ms.titusTaskInstanceID); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) localIPV4(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.localIPV4.count")
	if _, err := fmt.Fprint(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}

}

func (ms *MetadataServer) publicIPV4(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.publicIPV4.count")
	if ms.publicIpv4Address == nil {
		// The EC2 IMDS returns 404 if there's no public IPv4 address attached
		http.Error(w, notFoundBody, http.StatusNotFound)
		return
	}

	if _, err := fmt.Fprint(w, ms.publicIpv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-categories.html
// The private IPv4 DNS hostname of the instance. In cases where multiple network interfaces are present,
// this refers to the eth0 device (the device for which the device number is 0).
func (ms *MetadataServer) localHostname(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.localIPV4.count")
	if _, err := fmt.Fprint(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}

}

// The private IPv4 DNS hostname of the instance. In cases where multiple network interfaces are present,
// this refers to the eth0 device (the device for which the device number is 0).
func (ms *MetadataServer) hostname(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.hostname.count")
	if _, err := fmt.Fprint(w, ms.ipv4Address); err != nil {
		log.WithError(err).Error("Unable to write output")
	}
}

func (ms *MetadataServer) publicHostname(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.publicHostname.count")
	if _, err := fmt.Fprint(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) ping(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.ping.count")

	if _, err := fmt.Fprint(w, "ping called"); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) placementAZ(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.placementAZ.count")

	ctx := r.Context()
	az, err := ms.getAvailabilityZone(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get AZ")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, err := fmt.Fprint(w, az); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) placementAZID(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.placementAZID.count")

	ctx := r.Context()
	azID, err := ms.getAvailabilityZoneID(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get AZ ID")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, err := fmt.Fprint(w, azID); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) placementRegion(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.placementRegion.count")

	ctx := r.Context()
	region, err := ms.getRegion(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not get region")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if _, err := fmt.Fprint(w, region); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) getRegion(ctx context.Context) (string, error) {
	val, err, _ := ms.sf.Do("region", func() (interface{}, error) {
		if ms.region != "" {
			return ms.region, nil
		}
		region, err := ms.ec2metadatasvc.GetMetadataWithContext(ctx, "placement/region")
		if err == nil {
			ms.region = region
		}
		return region, err
	})

	if err != nil {
		return "", fmt.Errorf("Could not fetch current region from upstream IMDS: %w", err)
	}

	return val.(string), nil
}

func (ms *MetadataServer) getAvailabilityZone(ctx context.Context) (string, error) {
	val, err, _ := ms.sf.Do("availability-zone", func() (interface{}, error) {
		if ms.availabilityZone != "" {
			return ms.availabilityZone, nil
		}
		availabilityZone, err := ms.ec2metadatasvc.GetMetadataWithContext(ctx, "placement/availability-zone")
		if err == nil {
			ms.availabilityZone = availabilityZone
		}
		return availabilityZone, err
	})

	if err != nil {
		return "", fmt.Errorf("Could not fetch current availability-zone from upstream IMDS: %w", err)
	}

	return val.(string), nil
}

func (ms *MetadataServer) getAvailabilityZoneID(ctx context.Context) (string, error) {
	val, err, _ := ms.sf.Do("availability-zone-id", func() (interface{}, error) {
		if ms.availabilityZoneID != "" {
			return ms.availabilityZoneID, nil
		}
		availabilityZoneID, err := ms.ec2metadatasvc.GetMetadataWithContext(ctx, "placement/availability-zone-id")
		if err == nil {
			ms.availabilityZoneID = availabilityZoneID
		}
		return availabilityZoneID, err
	})

	if err != nil {
		return "", fmt.Errorf("Could not fetch current availability zone ID from upstream IMDS: %w", err)
	}

	return val.(string), nil
}

func (ms *MetadataServer) instanceIdentityDocument(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.instanceIdentityDocument.count")
	ctx := r.Context()
	region, err := ms.getRegion(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	az, err := ms.getAvailabilityZone(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	iid := map[string]interface{}{
		"devpayProductCodes":      nil,
		"marketplaceProductCodes": nil,
		"availabilityZone":        az,
		"privateIp":               ms.ipv4Address.String(),
		"version":                 "2017-09-30",
		"region":                  region,
		"instanceId":              ms.titusTaskInstanceID,
		"billingProducts":         nil,
		// This is a good question as to what we should put here
		"instanceType": "titus.large",
		"accountId":    ms.accountID,
		"PendingTime":  ms.launched.Format("2006-01-02T15:04:05Z"),
		// We might want to put the Docker Image Id here some day, but the chance someone is parsing it is a little
		// too high
		"imageId":      "ami-f00f",
		"kernelId":     nil,
		"ramdiskId":    nil,
		"architecture": "x86_64",
	}

	w.Header().Set("Content-type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	err = enc.Encode(iid)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not encode instance identity document response")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}

func (ms *MetadataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/* Ensure no request lasts longer than 10 seconds */
	ctx, cancel := context.WithTimeout(logging.WithConcurrentFields(r.Context()), 10*time.Second)
	r2 := r.WithContext(ctx)
	startTime := time.Now()
	defer cancel()
	defer func() {
		log.WithFields(logging.Entry(ctx)).WithField("request-time", time.Since(startTime).Milliseconds()).Infof("Request %s %s '%s' from %s", r2.Method, r2.RequestURI, r2.UserAgent(), r2.RemoteAddr)
	}()
	logging.AddFields(ctx, log.Fields{
		"method":        r.Method,
		"user-agent":    r.UserAgent(),
		"uri":           r.RequestURI,
		"path":          r.URL.Path,
		"token-present": len(r.Header.Get("X-aws-ec2-metadata-token")) > 0,
		"referer":       r.Header.Get("Referer"),
		"taskid":        ms.titusTaskInstanceID,
		"source-addr":   r.RemoteAddr,
		"assumed-arn":   ms.iamProxy.roles[ms.iamProxy.defaultRole].arn,
	})
	ms.internalMux.ServeHTTP(w, r2)
}

type proxy struct {
	backingMetadataServer *url.URL
	reverseProxy          *httputil.ReverseProxy
}

func newProxy(backingMetadataServer *url.URL) *proxy {
	p := &proxy{
		backingMetadataServer: backingMetadataServer,
		reverseProxy:          httputil.NewSingleHostReverseProxy(backingMetadataServer),
	}

	return p
}

func (p *proxy) checkProxyAllowed(path string) bool {
	return whitelist.Has(strings.TrimSuffix(path, "/"))
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logging.AddField(r.Context(), "proxied", true)
	metrics.PublishIncrementCounter("api.proxy_request.count")

	// Because the proxy should be mounted in the version
	if !p.checkProxyAllowed(r.URL.Path) {
		logging.AddField(r.Context(), "blocked", true)
		metrics.PublishIncrementCounter("api.proxy_request.blacklist.count")
		http.Error(w, "HTTP Proxy denied due to Netflix AWS Metdata proxy whitelist failure", http.StatusForbidden)
		return
	}

	r.Header.Del("x-aws-ec2-metadata-token")
	w.Header().Del("Server")
	metrics.PublishIncrementCounter("api.proxy_request.success.count")
	p.reverseProxy.ServeHTTP(w, r)

}
