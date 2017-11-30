package metadataserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Netflix/quitelite-client-go/properties"
	"github.com/Netflix/titus-executor/metadataserver/logging"
	"github.com/Netflix/titus-executor/metadataserver/metrics"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

// Derived from big data portal reports
const defaultMacAddress = "00:00:00:00:00:00"

const defaultWhiteList = `
/latest/meta-data/
/latest/meta-data/network/interfaces/macs/null/vpc-id
/latest/meta-data/network/interfaces/macs/00:00:00:00:00:00/vpc-id
/latest/dynamic/instance-identity
/latest/user-data
/latest/meta-data/placement/availability-zone
/latest/dynamic/instance-identity/document
/latest/meta-data/iam/
`

const whiteListEnabledByDefault = true

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
	ipv4Address         string
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
func NewMetaDataServer(ctx context.Context, backingMetadataServer, iamArn, titusTaskInstanceID, ipv4Address string) *MetadataServer {
	ms := &MetadataServer{
		httpClient:          &http.Client{},
		internalMux:         mux.NewRouter(),
		titusTaskInstanceID: titusTaskInstanceID,
		ipv4Address:         ipv4Address,
	}

	/* wire up routing */
	apiVersion := ms.internalMux.PathPrefix("/latest").Subrouter()
	apiVersion.NotFoundHandler = newProxy(backingMetadataServer)

	apiVersion.HandleFunc("/ping", ms.ping)
	/* Wire up the routes under /{VERSION}/meta-data */
	metaData := apiVersion.PathPrefix("/meta-data").Subrouter()
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
	newIamProxy(ctx, metaData.PathPrefix("/iam").Subrouter(), iamArn, titusTaskInstanceID)

	/* Dump debug routes if anyone cares */
	dumpRoutes(ms.internalMux)

	return ms
}

func (ms *MetadataServer) macAddr(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.macAddr.count")
	if _, err := fmt.Fprintf(w, defaultMacAddress); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) instanceID(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.instanceId.count")
	if _, err := fmt.Fprintf(w, ms.titusTaskInstanceID); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) localIPV4(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.localIPV4.count")
	if _, err := fmt.Fprintf(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}

}

func (ms *MetadataServer) publicIPV4(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.publicIPV4.count")
	if _, err := fmt.Fprintf(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

func (ms *MetadataServer) localHostname(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.localIPV4.count")
	if _, err := fmt.Fprintf(w, ms.ipv4Address); err != nil {
		log.Error("Unable to write output: ", err)
	}

}

func (ms *MetadataServer) publicHostname(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.publicHostname.count")
	if _, err := fmt.Fprintf(w, ms.ipv4Address); err != nil {
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
	whitelistEnabled int32
	whitelistLock    *sync.RWMutex
	whitelist        map[string]struct{}
	reverseProxy     *httputil.ReverseProxy
}

func newProxy(backingMetadataServer string) *proxy {
	u, err := url.Parse(backingMetadataServer)
	if err != nil {
		panic(err)
	}

	p := &proxy{
		whitelistLock: &sync.RWMutex{},
		whitelist:     make(map[string]struct{}),
		reverseProxy:  httputil.NewSingleHostReverseProxy(u),
	}
	if whiteListEnabledByDefault {
		p.whitelistEnabled = 1
	} else {
		p.whitelistEnabled = 0
	}

	p.maintainWhitelist()

	return p
}

func (p *proxy) checkProxyAllowed(path string) bool {
	if atomic.LoadInt32(&p.whitelistEnabled) == 0 {
		return true
	}
	p.whitelistLock.RLock()
	defer p.whitelistLock.RUnlock()
	_, ok := p.whitelist[path]
	return ok
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

	metrics.PublishIncrementCounter("api.proxy_request.success.count")
	p.reverseProxy.ServeHTTP(w, r)

}

func defaultWhitelistValue() string {
	if whiteListEnabledByDefault {
		return "true"
	}
	return "false"
}

func (p *proxy) maintainWhitelist() {
	whitelistEnabled := properties.NewDynamicProperty(context.TODO(), "titus.metadata.service.whitelist.enabled", defaultWhitelistValue(), "", nil)
	whitelist := properties.NewDynamicProperty(context.TODO(), "titus.metadata.service.whitelist.enabled", defaultWhiteList, "", nil)
	p.handleWhiteListEnabledValue(whitelistEnabled.Read())
	p.handleWhiteListValue(whitelistEnabled.Read())
	go p.maintainWhitelistEnabledValue(whitelistEnabled)
	go p.maintainWhitelistValue(whitelist)
}

func (p *proxy) maintainWhitelistEnabledValue(dp *properties.DynamicProperty) {
	for val := range dp.C {
		p.handleWhiteListEnabledValue(val)
	}
}

func (p *proxy) maintainWhitelistValue(dp *properties.DynamicProperty) {
	for val := range dp.C {
		p.handleWhiteListValue(val)
	}
}

func (p *proxy) handleWhiteListEnabledValue(whitelistEnabled *properties.DynamicPropertyValue) {
	if val, err := whitelistEnabled.AsBool(); err != nil {
		log.Error("Could not parse whitelist value, because: ", err)
	} else if val {
		atomic.StoreInt32(&p.whitelistEnabled, 1)
	} else {
		atomic.StoreInt32(&p.whitelistEnabled, 0)
	}
}

func (p *proxy) handleWhiteListValue(whitelistPropertyValue *properties.DynamicPropertyValue) {

	whitelist, err := whitelistPropertyValue.AsString()
	if err != nil {
		log.Error("Could not get whitelist string: ", err)
		return
	}
	newWhiteList := map[string]struct{}{}
	// We split on , or "\n"
	newLineSplitWhiteListValue := strings.Split(whitelist, "\n")

	splitWhiteListValue := []string{}
	for _, val := range newLineSplitWhiteListValue {
		splitWhiteListValue = append(splitWhiteListValue, strings.Split(val, ",")...)
	}
	/* We normalize the list so if someone puts /foo/bar/ in the list, then /foo/bar is also allowed,
	 * similarly if someone puts /foo/bar in the whitelist, then /foo/bar/ is allowed
	 */
	for _, val := range splitWhiteListValue {
		noTrailingSlash := strings.TrimSuffix(val, "/")
		withTrailingSlash := noTrailingSlash + "/"
		newWhiteList[noTrailingSlash] = struct{}{}
		newWhiteList[withTrailingSlash] = struct{}{}
	}
	p.whitelistLock.Lock()
	defer p.whitelistLock.Unlock()
	p.whitelist = newWhiteList
}
