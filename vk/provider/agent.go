package provider

import (
	"context"
	"fmt"
	"github.com/cpuguy83/strongerrors"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"github.com/virtual-kubelet/virtual-kubelet/providers/register"
	"io"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"net"
	"os"
	"strings"
	"sync"
)

var (
	_ providers.Provider = (*AgentProvider)(nil)
	_ providers.PodNotifier = (*AgentProvider)(nil)

	cpu = resource.MustParse("1024")
	memory = resource.MustParse("500G")
	disk = resource.MustParse("1000G")
)

type AgentProvider struct {
	lock sync.Mutex
	pods map[types.UID]*runtimePod
	lastStateTransitionTime metav1.Time
	daemonEndpointPort int32
	notifier func(*v1.Pod)
}

func NewAgentProvider(config register.InitConfig) *AgentProvider {
	return &AgentProvider{
		pods: make(map[types.UID]*runtimePod),
		lastStateTransitionTime: metav1.Now(),
		daemonEndpointPort: config.DaemonPort,
	}
}

// CreatePod takes a Kubernetes Pod and deploys it within the provider.
func (a *AgentProvider) CreatePod(ctx context.Context, pod *v1.Pod) error {
	log.G(ctx).WithField("podName", pod.Name).Info("CreatePod")

	a.lock.Lock()
	defer a.lock.Unlock()

	rp := &runtimePod{
		pod: pod,
		provider: a,
	}

	if err := rp.run(ctx); err != nil {
		return err
	}
	a.pods[pod.UID] = rp

	return nil
}

// UpdatePod takes a Kubernetes Pod and updates it within the provider.
func (a *AgentProvider) UpdatePod(ctx context.Context, pod *v1.Pod) error {
	log.G(ctx).WithField("podName", pod.Name).Info("UpdatePod")
	panic("Not implemented")
}

// DeletePod takes a Kubernetes Pod and deletes it from the provider.
func (a *AgentProvider) DeletePod(ctx context.Context, pod *v1.Pod) error {
	log.G(ctx).WithField("podName", pod.Name).Info("DeletePod")

	a.lock.Lock()
	defer a.lock.Unlock()

	if rp, ok := a.pods[pod.UID]; !ok {
		return strongerrors.NotFound(fmt.Errorf("Pod %q not found", pod.Name))
	} else {
		return rp.delete(ctx)
	}

	return nil
}

// GetPod retrieves a pod by name from the provider (can be cached).
func (a *AgentProvider) GetPod(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	log.G(ctx).WithField("podName", name).Info("GetPod")
	return nil, nil
}

// GetContainerLogs retrieves the logs of a container by name from the provider.
func (a *AgentProvider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts providers.ContainerLogOpts) (io.ReadCloser, error) {
	log.G(ctx).WithField("podName", podName).Info("GetContainerLogs")
	return nil, nil
}

// RunInContainer executes a command in a container in the pod, copying data
// between in/out/err and the container's stdin/stdout/stderr.
func (a *AgentProvider) RunInContainer(ctx context.Context, namespace, podName, containerName string, cmd []string, attach providers.AttachIO) error {
	log.G(ctx).WithField("podName", podName).Info("RunInContainer")
	return nil
}

// GetPodStatus retrieves the status of a pod by name from the provider.
func (a *AgentProvider) GetPodStatus(ctx context.Context, namespace, name string) (*v1.PodStatus, error) {
	log.G(ctx).WithField("podName", name).Info("GetPodStatus")
	return nil, nil
}

// GetPods retrieves a list of all pods running on the provider (can be cached).
func (a *AgentProvider) GetPods(ctx context.Context) ([]*v1.Pod, error) {
	log.G(ctx).Info("GetPods")

	a.lock.Lock()
	defer a.lock.Unlock()

	resp := []*v1.Pod{}
	for _, ns := range a.pods {
		if pod := ns.getPod(ctx); pod != nil {
			resp = append(resp, pod)
		}
	}

	return resp, nil
}

// Capacity returns a resource list with the capacity constraints of the provider.
func (a *AgentProvider) Capacity(ctx context.Context) v1.ResourceList {
	log.G(ctx).Info("Capacity")

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

// NodeConditions returns a list of conditions (Ready, OutOfDisk, etc), which is
// polled periodically to update the node status within Kubernetes.
func (a *AgentProvider) NodeConditions(ctx context.Context) []v1.NodeCondition {
	log.G(ctx).Info("NodeConditions")

	return []v1.NodeCondition{
		{
			Type:               "Ready",
			Status:             v1.ConditionTrue,
			LastHeartbeatTime:  metav1.Now(),
			LastTransitionTime: a.lastStateTransitionTime,
			Reason:             "KubeletReady",
			Message:            "kubelet is ready.",
		},
	}
}

// NodeAddresses returns a list of addresses for the node status
// within Kubernetes.
func (a *AgentProvider) NodeAddresses(ctx context.Context) []v1.NodeAddress {
	log.G(ctx).Info("NodeAddresses")
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

// NodeDaemonEndpoints returns NodeDaemonEndpoints for the node status
// within Kubernetes.
func (a *AgentProvider) NodeDaemonEndpoints(ctx context.Context) *v1.NodeDaemonEndpoints {
	log.G(ctx).Info("NodeDaemonEndpoints")
	return &v1.NodeDaemonEndpoints{
		KubeletEndpoint: v1.DaemonEndpoint{
			Port: a.daemonEndpointPort,
		},
	}
}

// OperatingSystem returns the operating system the provider is for.
func (a *AgentProvider) OperatingSystem() string {
	return "Linux"
}

func (a *AgentProvider) NotifyPods(ctx context.Context, notifier func(*v1.Pod)) {
	log.G(ctx).Info("NotifyPods")
	a.notifier = notifier
}

