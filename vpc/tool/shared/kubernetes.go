package shared

import (
	"fmt"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

func PodKey(pod *corev1.Pod) string {
	return pod.Name
}

func ToPodList(body []byte) (*corev1.PodList, error) {
	// Borrowed from: https://gist.github.com/nownabe/4345d9b68f323ba30905c9dfe3460006

	// https://godoc.org/k8s.io/apimachinery/pkg/runtime#Scheme
	scheme := runtime.NewScheme()

	// https://godoc.org/k8s.io/apimachinery/pkg/runtime/serializer#CodecFactory
	codecFactory := serializer.NewCodecFactory(scheme)

	// https://godoc.org/k8s.io/apimachinery/pkg/runtime#Decoder
	deserializer := codecFactory.UniversalDeserializer()

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
