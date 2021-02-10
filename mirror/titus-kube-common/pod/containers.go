package pod

import (
	corev1 "k8s.io/api/core/v1"
)

func GetUserContainer(pod *corev1.Pod) *corev1.Container {
	firstContainer := pod.Spec.Containers[0]
	for _, c := range pod.Spec.Containers {
		if c.Name == pod.Name {
			ctr := c
			return &ctr
		}
	}

	return &firstContainer
}
