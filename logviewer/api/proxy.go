package api

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/Netflix/titus-executor/logviewer/conf"
	"github.com/Netflix/titus-executor/utils"
	"github.com/Netflix/titus-executor/utils/netns"
	"github.com/Netflix/titus-executor/vpc/tool/cni"
)

// The URL to connect to once we've done a Setns() into the container
const inContainerURL = "http://127.0.0.1:8004"

func getNetNsPath(containerID string) string {
	if conf.KubeletMode {
		return cni.NSAliasPath(containerID)
	}

	return fmt.Sprintf("%s/%s/ns/net", utils.TitusInits, containerID)
}

func getKubeletNetNsPath(podID string) string {
	return fmt.Sprintf("/var/run/pod/netns-%s", podID)
}

func doProxy(w http.ResponseWriter, r *http.Request, containerID string, proxy *httputil.ReverseProxy) {
	proxyURL, _ := url.Parse(inContainerURL)

	nsPath := getNetNsPath(containerID)
	nsDialer, err := netns.NewNsDialer(nsPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// These values were taken from http.DefaultTransport
	proxyTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           nsDialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if proxy == nil {
		proxy = httputil.NewSingleHostReverseProxy(proxyURL)
	}
	proxy.Transport = proxyTransport
	proxy.ServeHTTP(w, r)
}

// LogProxyHandler is an HTTP handler that proxies /logs/:containerid/... to the in-container logviewer
func LogProxyHandler(w http.ResponseWriter, r *http.Request) {
	containerID, err := containerIDFromURL(r.URL.Path, logsExp)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	doProxy(w, r, containerID, nil)
}

// LogViewerProxyHandler is an HTTP handler that proxies all requests to the underlying logviewer,
// so `/logviewer/:id/foo` will hit `/foo` on the in-container logviewer
func LogViewerProxyHandler(w http.ResponseWriter, r *http.Request) {
	containerID, err := containerIDFromURL(r.URL.Path, logViewerExp)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	proxyURL, _ := url.Parse(inContainerURL)
	director := func(req *http.Request) {
		req.URL.Scheme = proxyURL.Scheme
		req.URL.Host = proxyURL.Host
		req.URL.Path = logViewerExp.ReplaceAllString(req.URL.Path, "")

		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	proxy := &httputil.ReverseProxy{Director: director}
	doProxy(w, r, containerID, proxy)
}

// ListLogsProxyHandler is an HTTP handler that proxies /listlogs/:containerid/... to the in-container logviewer
func ListLogsProxyHandler(w http.ResponseWriter, r *http.Request) {
	containerID, err := containerIDFromURL(r.URL.Path, listLogsExp)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	doProxy(w, r, containerID, nil)
}

func RegisterProxyHandlers(r *http.ServeMux) {
	r.HandleFunc("/listlogs/", ListLogsProxyHandler)
	r.HandleFunc("/logs/", LogProxyHandler)
	r.HandleFunc("/logviewer/", LogViewerProxyHandler)
}
