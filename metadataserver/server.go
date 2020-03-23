package metadataserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/logging"
	"github.com/Netflix/titus-executor/metadataserver/metrics"
	"github.com/Netflix/titus-executor/metadataserver/types"
	set "github.com/deckarep/golang-set"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// Derived from big data portal reports
const defaultMacAddress = "00:00:00:00:00:00"

var whitelist = set.NewSetFromSlice([]interface{}{
	"/latest/meta-data",
	"/latest/meta-data/network/interfaces/macs/null/vpc-id",
	"/latest/meta-data/network/interfaces/macs/00:00:00:00:00:00/vpc-id",
	"/latest/dynamic/instance-identity",
	"/latest/user-data",
	"/latest/meta-data/placement/availability-zone",
	"/latest/dynamic/instance-identity/document",
	"/latest/meta-data/iam",
})

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
	/*
		The below stuff could be called *instance specific metadata*
		I'd rather not break it into owns struct
	*/
	titusTaskInstanceID string
	ipv4Address         net.IP
	ipv6Address         *net.IP
	vpcID               string
	eniID               string
	container           *titus.ContainerInfo
	signer              *identity.Signer
	// Need to hold `signLock` while accessing `signer`
	signLock                  sync.RWMutex
	tokenRequired             bool
	tokenKey                  []byte
	xForwardedForBlockingMode bool
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
func NewMetaDataServer(ctx context.Context, config types.MetadataServerConfiguration) *MetadataServer {
	ms := &MetadataServer{
		httpClient:                &http.Client{},
		internalMux:               mux.NewRouter(),
		titusTaskInstanceID:       config.TitusTaskInstanceID,
		ipv4Address:               config.Ipv4Address,
		ipv6Address:               config.Ipv6Address,
		vpcID:                     config.VpcID,
		eniID:                     config.EniID,
		container:                 config.Container,
		signer:                    config.Signer,
		tokenRequired:             config.RequireToken,
		xForwardedForBlockingMode: config.XFordwardedForBlockingMode,
	}

	ms.tokenKey = []byte(config.TokenKey)

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

	return ms
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
	metaData.HandleFunc("/public-hostname", ms.publicHostname)

	/* Specifically return 404 on these endpoints */
	metaData.Handle("/ami-id", http.NotFoundHandler())
	metaData.Handle("/instance-type", http.NotFoundHandler())

	/* IAM Stuffs */
	newIamProxy(ctx, metaData.PathPrefix("/iam").Subrouter(), config)

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
	if _, err := fmt.Fprint(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) localHostname(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.localIPV4.count")
	if _, err := fmt.Fprint(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
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

	if _, err := fmt.Fprintf(w, "ping called"); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/* Ensure no request lasts longer than 10 seconds */
	ctx, cancel := context.WithTimeout(logging.WithConcurrentFields(r.Context()), 10*time.Second)
	r2 := r.WithContext(ctx)
	defer cancel()
	defer func() {
		log.WithFields(logging.Entry(ctx)).Infof("Request %s %s '%s'", r2.Method, r2.RequestURI, r2.UserAgent())
	}()
	logging.AddFields(ctx, log.Fields{
		"method":     r.Method,
		"user-agent": r.UserAgent(),
		"uri":        r.RequestURI,
		"path":       r.URL.Path,
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
	return whitelist.Contains(strings.TrimSuffix(path, "/"))
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
	metrics.PublishIncrementCounter("api.proxy_request.success.count")
	p.reverseProxy.ServeHTTP(w, r)

}
