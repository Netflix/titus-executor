package vk

import (
	"github.com/cpuguy83/strongerrors"
	"github.com/pkg/errors"
	"github.com/virtual-kubelet/virtual-kubelet/cmd/virtual-kubelet/commands/root"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
)

const (
	DefaultTaintEffect = string(corev1.TaintEffectNoSchedule)
	DefaultTaintKey    = "virtual-kubelet.io/provider"
)
// getTaint creates a taint using the provided key/value.
// Taint effect is read from the environment
// The taint key/value may be overwritten by the environment.
func getTaint(c root.Opts) (*corev1.Taint, error) {
	value := c.Provider

	key := c.TaintKey
	if key == "" {
		key = DefaultTaintKey
	}

	if c.TaintEffect == "" {
		c.TaintEffect = DefaultTaintEffect
	}

	key = getEnv("VKUBELET_TAINT_KEY", key)
	value = getEnv("VKUBELET_TAINT_VALUE", value)
	effectEnv := getEnv("VKUBELET_TAINT_EFFECT", string(c.TaintEffect))

	var effect corev1.TaintEffect
	switch effectEnv {
	case "NoSchedule":
		effect = corev1.TaintEffectNoSchedule
	case "NoExecute":
		effect = corev1.TaintEffectNoExecute
	case "PreferNoSchedule":
		effect = corev1.TaintEffectPreferNoSchedule
	default:
		return nil, strongerrors.InvalidArgument(errors.Errorf("taint effect %q is not supported", effectEnv))
	}

	return &corev1.Taint{
		Key:    key,
		Value:  value,
		Effect: effect,
	}, nil
}

func newClient(configPath string) (*kubernetes.Clientset, error) {
	var config *rest.Config

	// Check if the kubeConfig file exists.
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		// Get the kubeconfig from the filepath.
		config, err = clientcmd.BuildConfigFromFlags("", configPath)
		if err != nil {
			return nil, errors.Wrap(err, "error building client config")
		}
	} else {
		// Set to in-cluster config.
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, errors.Wrap(err, "error building in cluster config")
		}
	}

	if masterURI := os.Getenv("MASTER_URI"); masterURI != "" {
		config.Host = masterURI
	}

	return kubernetes.NewForConfig(config)
}



func getEnv(key, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if found {
		return value
	}
	return defaultValue
}
