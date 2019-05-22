package vk

import (
	"context"
	"fmt"
	"github.com/Netflix/titus-executor/vk/provider"
	"github.com/pkg/errors"
	"github.com/virtual-kubelet/virtual-kubelet/cmd/virtual-kubelet/commands/root"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/manager"
	"github.com/virtual-kubelet/virtual-kubelet/providers"
	"github.com/virtual-kubelet/virtual-kubelet/providers/register"
	"github.com/virtual-kubelet/virtual-kubelet/vkubelet"
	"k8s.io/api/core/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"
)

var (
 errPodNotFound = errors.New("Pod not found")
)
type Vk struct {
	lastStateTransitionTime metav1.Time
	daemonEndpointPort      int32
	clientset               *kubernetes.Clientset
}

func NewVk() (*Vk, error) {
	vk :=  &Vk{}
	/*
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	vk :=  &Vk{
		lastStateTransitionTime: metav1.Now(),
		pods: make(map[podKey]*v1.Pod),
		clientset: clientset,
	}
	*/
	return vk, nil
}


func (vk *Vk) Start(ctx context.Context) error {
	var err error
	var c = root.Opts{}
	c.NodeName, err = os.Hostname()
	if err != nil {
		return err
	}
	err = root.SetDefaultOpts(&c)
	if err != nil {
		panic(err)
	}

	var taint *corev1.Taint
	/* Leave the taint always disabled for now
	if !c.DisableTaint {
		var err error
		taint, err = getTaint(c)
		if err != nil {
			panic(err)
		}
	}
	*/

	client, err := newClient(c.KubeConfigPath)
	if err != nil {
		panic(err)
	}

	// Create a shared informer factory for Kubernetes pods in the current namespace (if specified) and scheduled to the current node.
	podInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(
		client,
		c.InformerResyncPeriod,
		kubeinformers.WithNamespace(c.KubeNamespace),
		kubeinformers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", c.NodeName).String()
		}))
	// Create a pod informer so we can pass its lister to the resource manager.
	podInformer := podInformerFactory.Core().V1().Pods()

	// Create another shared informer factory for Kubernetes secrets and configmaps (not subject to any selectors).
	scmInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(client, c.InformerResyncPeriod)
	// Create a secret informer and a config map informer so we can pass their listers to the resource manager.
	secretInformer := scmInformerFactory.Core().V1().Secrets()
	configMapInformer := scmInformerFactory.Core().V1().ConfigMaps()
	serviceInformer := scmInformerFactory.Core().V1().Services()

	go podInformerFactory.Start(ctx.Done())
//	go scmInformerFactory.Start(ctx.Done())

	rm, err := manager.NewResourceManager(podInformer.Lister(), secretInformer.Lister(), configMapInformer.Lister(), serviceInformer.Lister())
	if err != nil {
		panic(errors.Wrap(err, "could not create resource manager"))
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(log.Fields{
		"provider":         c.Provider,
		"operatingSystem":  c.OperatingSystem,
		"node":             c.NodeName,
		"watchedNamespace": c.KubeNamespace,
	}))

	apiConfig, err := getAPIConfig(c)
	if err != nil {
		return err
	}

	initConfig := register.InitConfig{
		ConfigPath:      c.ProviderConfigPath,
		NodeName:        c.NodeName,
		OperatingSystem: c.OperatingSystem,
		ResourceManager: rm,
		DaemonPort:      int32(c.ListenPort),
		InternalIP:      os.Getenv("VKUBELET_POD_IP"),
	}

	p, err := provider.NewProvider(initConfig)
	if err != nil {
		return err
	}



	pNode := NodeFromProvider(ctx, c.NodeName, taint, p)
	log.G(ctx).WithField("pod", pNode).Info("Registering node")
	node, err := vkubelet.NewNode(
		vkubelet.NaiveNodeProvider{},
		pNode,
		client.CoordinationV1beta1().Leases(corev1.NamespaceNodeLease),
		client.CoreV1().Nodes(),
		vkubelet.WithNodeDisableLease(!c.EnableNodeLease),
	)
	if err != nil {
		log.G(ctx).Fatal(err)
	}

	vKubelet := vkubelet.New(vkubelet.Config{
		Client:          client,
		Namespace:       c.KubeNamespace,
		NodeName:        pNode.Name,
		Provider:        p,
		ResourceManager: rm,
		PodSyncWorkers:  c.PodSyncWorkers,
		PodInformer:     podInformer,
	})

	cancelHTTP, err := setupHTTPServer(ctx, p, apiConfig)
	if err != nil {
		return err
	}
	defer cancelHTTP()

	go func() {
		if err := vKubelet.Run(ctx); err != nil && errors.Cause(err) != context.Canceled {
			log.G(ctx).Fatal(err)
		}
	}()

	go func() {
		if err := node.Run(ctx); err != nil {
			log.G(ctx).Fatal(err)
		}
	}()

	log.G(ctx).Info("Initialized")

	<-ctx.Done()
	return nil
}


func mesosAttributesAsAnnotations(ctx context.Context) map[string]string {

	annotations := map[string]string{}
	       mesosAttributes := os.Getenv("MESOS_ATTRIBUTES")
	       if mesosAttributes == "" {
		               log.G(ctx).Warn("Cannot fetch mesos attributes")
		               return annotations
		       }
	       for _, attribute := range strings.Split(mesosAttributes, ";")    {
		               attributeKV := strings.SplitN(attribute, ":", 2)
		               if len(attributeKV) != 2 {
			                       panic(fmt.Sprintf("Attribute %s did not split into two parts", attribute))
			               }
		               annotationKey := fmt.Sprintf("com.netflix.titus.agent.attribute/%s", attributeKV[0])
		               annotations[annotationKey] = attributeKV[1]
		       }
	return annotations
	}



// NodeFromProvider builds a kubernetes node object from a provider
// This is a temporary solution until node stuff actually split off from the provider interface itself.
func NodeFromProvider(ctx context.Context, name string, taint *v1.Taint, p providers.Provider) *v1.Node {
	taints := make([]v1.Taint, 0)

	if taint != nil {
		taints = append(taints, *taint)
	}

	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"type":                   "virtual-kubelet",
				"kubernetes.io/role":     "agent",
				"beta.kubernetes.io/os":  strings.ToLower(p.OperatingSystem()),
				"kubernetes.io/hostname": name,
				"alpha.service-controller.kubernetes.io/exclude-balancer": "true",
			},
			Annotations: mesosAttributesAsAnnotations(ctx),
		},
		Spec: v1.NodeSpec{
			Taints: taints,
		},
		Status: v1.NodeStatus{
			NodeInfo: v1.NodeSystemInfo{
				OperatingSystem: p.OperatingSystem(),
				Architecture:    "amd64",
				KubeletVersion:  "1",
			},
			Capacity:        p.Capacity(ctx),
			Allocatable:     p.Capacity(ctx),
			Conditions:      p.NodeConditions(ctx),
			Addresses:       p.NodeAddresses(ctx),
			DaemonEndpoints: *p.NodeDaemonEndpoints(ctx),
		},
	}



	return node
}
