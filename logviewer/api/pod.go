package api

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	namespace = "default"
)

type podLogsHandler struct {
	clientset *kubernetes.Clientset
}

// ListLogsPodHandler is an HTTP handler to proxy /listlogs/:podid/... to the in-pod logviewer
func (h *podLogsHandler) ListLogsPodHandler(w http.ResponseWriter, r *http.Request) {
	podID, err := containerIDFromURL(r.URL.Path, listLogsExp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	h.proxyToPod(podID, w, r)
}

// LogPodHandler is an HTTP handler that proxies /logs/:podid/... to the in-pod log viewer
func (h *podLogsHandler) LogPodHandler(w http.ResponseWriter, r *http.Request) {
	podID, err := containerIDFromURL(r.URL.Path, logsExp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	h.proxyToPod(podID, w, r)
}

func (h *podLogsHandler) proxyToPod(podID string, w http.ResponseWriter, r *http.Request) {
	pod, err := h.clientset.CoreV1().Pods(namespace).Get(r.Context(), podID, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	IP := pod.Status.PodIP
	if IP == "" {
		http.Error(w, "No IP found for the targetted pod", http.StatusNotFound)
		return
	}
	url, err := url.Parse("http://" + IP + ":8004")
	if err != nil {
		http.Error(w, "Unable to parse upstream url", http.StatusInternalServerError)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.ServeHTTP(w, r)
}

// RegisterPodHandlers registers the interface handlers for handling logvieweing all of these are proxies to the underlying web server running in the pod.
func RegisterPodHandlers(r *http.ServeMux) {

	kubeconfig, ok := os.LookupEnv("KUBERNETES_CONFIG")
	if !ok {
		log.Fatal("KUBERNETES_CONFIG not set, unable to lookup pods for proxy")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.WithFields(log.Fields{
			"error":      err,
			"kubeconfig": kubeconfig,
		}).Fatal("Unable to build kubernetes client config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("Unable to create kubernetes client")
	}

	handler := podLogsHandler{
		clientset: clientset,
	}

	r.HandleFunc("/listlogs/", handler.ListLogsPodHandler)
	r.HandleFunc("/logs/", handler.LogPodHandler)
}
