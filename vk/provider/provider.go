package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cpuguy83/strongerrors"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"github.com/virtual-kubelet/virtual-kubelet/providers/register"
	"golang.org/x/sys/unix"
	"io"
	"io/ioutil"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/remotecommand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	_ providers.Provider = (*Provider)(nil)
	_ providers.PodNotifier = (*Provider)(nil)

	cpu = resource.MustParse("1024")
	memory = resource.MustParse("500G")
	disk = resource.MustParse("1000G")

	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
	codec = codecs.LegacyCodec(v1.SchemeGroupVersion)
)

type runtimePod struct {
	lock     sync.Mutex
	pod      *v1.Pod
	lastPod  *v1.Pod
	provider *Provider
	cmd      *exec.Cmd
	killTimer *time.Timer
}

func (rp *runtimePod) run(ctx context.Context) error {
	rp.lastPod = rp.pod
	// This should be configurable, I'm just being lazy
	path, err := exec.LookPath("./virtual-kubelet-backend")
	if err != nil {
		return err
	}

	f, err := ioutil.TempFile("", "pod")
	err = json.NewEncoder(f).Encode(rp.pod)
	f.Sync()
	f.Close()
	if err != nil {
		return err
	}

	log.G(ctx).WithField("filename", f.Name()).Info("Created podspec")
	rp.cmd = exec.CommandContext(ctx, path, "--pod", f.Name())
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	rp.cmd.Stdout = stdoutWriter
	rp.cmd.Stderr = os.Stderr
	err = rp.cmd.Start()
	if err != nil {
		return err
	}
	go rp.monitor(ctx, stdoutReader)
	go rp.statusUpdater(ctx, stdoutReader)
	return nil
}

func (rp *runtimePod) statusUpdater(ctx context.Context, stdoutReader *os.File) {
	decoder := json.NewDecoder(stdoutReader)
	for {
		pod := v1.Pod{}
		err := decoder.Decode(&pod)
		log.G(ctx).WithField("podStatus", pod.Status).Info("Decoded pod (status)")
		if err != nil {
			rp.cmd.Process.Kill()
			return
		}
		rp.provider.notifier(&pod)
		rp.lock.Lock()
		rp.lastPod = &pod
		rp.lock.Unlock()
	}
}

func (rp *runtimePod) monitor(ctx context.Context, stdoutReader *os.File) {
	err := rp.cmd.Wait()
	if err != nil {
		log.G(ctx).WithError(err).Info("RP terminated")
	}
	rp.lock.Lock()
	if rp.pod.Status.Phase != v1.PodFailed || rp.pod.Status.Phase != v1.PodSucceeded {
		log.G(ctx).Error("TODO: Set pod to failed")
	}
	rp.lock.Unlock()
}


func (rp *runtimePod) delete(ctx context.Context) error {
	rp.lock.Lock()
	defer rp.lock.Unlock()
	rp.killTimer = time.AfterFunc(5 * time.Minute, func() {rp.cmd.Process.Kill()})
	return 	rp.cmd.Process.Signal(unix.SIGUSR1)
}

func (rp *runtimePod) getPod(ctx context.Context) *v1.Pod {
	rp.lock.Lock()
	defer rp.lock.Unlock()
	return rp.lastPod
}

type Provider struct {
	lock sync.Mutex
	pods                    map[types.UID]*runtimePod
	lastStateTransitionTime metav1.Time
	daemonEndpointPort int32
	notifier func(*v1.Pod)
}

func (p *Provider) NotifyPods(ctx context.Context, notifier func(*v1.Pod)) {
	p.notifier = notifier
}

func (p *Provider) RunInContainer(ctx context.Context, namespace, podName, containerName string, cmd []string, attach providers.AttachIO) error {
	panic("implement me")
}


func (p *Provider) CreatePod(ctx context.Context, pod *v1.Pod) error {
	p.lock.Lock()
	defer p.lock.Unlock()
	rp := &runtimePod{
		pod: pod,
		lastPod: pod,
		provider: p,
	}
	if err := rp.run(ctx); err != nil {
		return err
	}
	p.pods[pod.UID] = rp

	return nil
}

func (p *Provider) UpdatePod(ctx context.Context, pod *v1.Pod) error {
	panic("Not implemented")
}

func (p *Provider) DeletePod(ctx context.Context, pod *v1.Pod) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if rp, ok := p.pods[pod.UID]; !ok {
		return strongerrors.NotFound(fmt.Errorf("Pod %q not found", pod.Name))
	} else {
		return rp.delete(ctx)
	}

	return nil
}

func (p *Provider) GetPod(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	panic("Unimplemented")
}

func (p *Provider) GetContainerLogs(context.Context, string, string, string, providers.ContainerLogOpts) (io.ReadCloser, error) {
	panic("implement me")
}

func (p *Provider) ExecInContainer(string, types.UID, string, []string, io.Reader, io.WriteCloser, io.WriteCloser, bool, <-chan remotecommand.TerminalSize, time.Duration) error {
	panic("implement me")
}

func (p *Provider) GetPodStatus(ctx context.Context, namespace, name string) (*v1.PodStatus, error) {
	panic("implement me")
}

func (p *Provider) GetPods(ctx context.Context) ([]*v1.Pod, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	resp := []*v1.Pod{}
	for _, ns := range p.pods {
		if pod := ns.getPod(ctx); pod != nil {
			resp = append(resp, pod)
		}
	}
	return resp, nil
}

func (p *Provider) Capacity(ctx context.Context) v1.ResourceList {
	resourceList := v1.ResourceList{
		v1.ResourceCPU:     (cpu),
		v1.ResourceMemory:  (memory),
		v1.ResourceStorage: (disk),
	}

	mesosResources := os.Getenv("MESOS_RESOURCES")
	if mesosResources == "" {
		log.G(ctx).Warn("Cannot fetch mesos resources")
		return resourceList
	}

	for _, r := range strings.Split(mesosResources, ";") {
		resourceKV := strings.SplitN(r, ":", 2)
		if len(resourceKV) != 2 {
			panic(fmt.Sprintf("Cannot parse resource: %s", r))
		}
		switch resourceKV[0] {
		case "mem":
			resourceList[v1.ResourceMemory] = resource.MustParse(resourceKV[1])
		case "disk":
			resourceList[v1.ResourceStorage] = resource.MustParse(resourceKV[1])
		case "cpu":
			resourceList[v1.ResourceCPU] = resource.MustParse(resourceKV[1])
		case "network":
			resourceList["network"] = resource.MustParse(resourceKV[1])
		}
	}

	return resourceList
}

func (p *Provider) NodeConditions(context.Context) []v1.NodeCondition {
	return []v1.NodeCondition{
		{
			Type:               "Ready",
			Status:             v1.ConditionTrue,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: p.lastStateTransitionTime,
			Reason:             "KubeletReady",
			Message:            "kubelet is ready.",
		},
	}
}

func (p *Provider) NodeAddresses(ctx context.Context) []v1.NodeAddress {
	nodeAddresses := []v1.NodeAddress{}

	hostname, err := os.Hostname()
	if err != nil {
		log.G(ctx).WithError(err).Warn("Cannot get hostname")
		return nodeAddresses
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil {
		log.G(ctx).WithError(err).Warn("Cannot resolve hostname")
		return nodeAddresses
	}
	if len(addrs) == 0 {
		log.G(ctx).Warn("Zero node addresses found")
		return nodeAddresses
	}

	for _, addr := range addrs {
		nodeAddresses = append(nodeAddresses, v1.NodeAddress{
			Type:    v1.NodeInternalIP,
			Address: addr,
		})
	}

	return nodeAddresses
}

func (p *Provider) NodeDaemonEndpoints(context.Context) *v1.NodeDaemonEndpoints {
	return &v1.NodeDaemonEndpoints{
		KubeletEndpoint: v1.DaemonEndpoint{
			Port: p.daemonEndpointPort,
		},
	}
}

func (p *Provider) OperatingSystem() string {
	return "Linux"
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(p.pods)
}

func NewProvider(config register.InitConfig) (*Provider, error) {
	p := &Provider{
		pods: make(map[types.UID]*runtimePod),
		lastStateTransitionTime: metav1.Now(),
		daemonEndpointPort: config.DaemonPort,
	}

	srv := http.Server{
		Addr: "0.0.0.0:5656",
		Handler: p,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			logrus.WithError(err).Fatal("Backend server failed")
		}
	}()
	return p, nil
}




