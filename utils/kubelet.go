package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/containernetworking/cni/pkg/types"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

func PodKey(pod *corev1.Pod) string {
	return pod.Name
}

func ToPodList(body []byte) (*corev1.PodList, error) {
	deserializer := serializer.NewCodecFactory(runtime.NewScheme()).UniversalDeserializer()

	podListObject, _, err := deserializer.Decode(body, nil, &corev1.PodList{})
	if err != nil {
		err = errors.Wrap(err, "Cannot deserialize podlist from kubelet")
		return nil, err
	}

	podList, ok := podListObject.(*corev1.PodList)
	if !ok {
		return nil, fmt.Errorf("Could not cast podlistobject, as it's type is: %s", podListObject.GetObjectKind().GroupVersionKind().String())
	}

	return podList, nil
}

func GetPod(ctx context.Context, url string, args K8sArgs) (*corev1.Pod, error) {
	body, err := Get(ctx, url)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to fetch from Kubernetes URL")
	}

	podList, err := ToPodList(body)
	if err != nil {
		return nil, errors.Wrap(err, "Unable deserialize pods body from kubelet")
	}

	namespace := string(args.K8S_POD_NAMESPACE)
	name := string(args.K8S_POD_NAME)
	for idx := range podList.Items {
		pod := podList.Items[idx]
		if pod.Namespace == namespace && pod.Name == name {
			return &pod, nil
		}
	}

	err = fmt.Errorf("Could not find pod %s, in namespace %s", name, namespace)
	return nil, err
}

func Get(ctx context.Context, url string) ([]byte, error) {
	customTransport := &http.Transport{
		MaxIdleConns: 0,
		// The certificate that the VK loads isn't reloaded periodically, so it can go stale. Therefore,
		// the easiest option is to skip verify, especially because it's on localhost.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint: gosec
	}
	client := &http.Client{
		Transport: customTransport,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Add("Accept", "application/json")
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create new request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to do request")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return ioutil.ReadAll(resp.Body)
}

// Refer https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/dockershim/network/cni/cni.go#L392
type K8sArgs struct {
	types.CommonArgs

	K8S_POD_NAME               types.UnmarshallableString // nolint:golint
	K8S_POD_NAMESPACE          types.UnmarshallableString // nolint:golint
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString // nolint:golint
}
