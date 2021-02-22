package pod

import (
	corev1 "k8s.io/api/core/v1"
)

func GetUserContainer(pod *corev1.Pod) *corev1.Container {
	firstContainer := pod.Spec.Containers[0]
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == pod.Name {
			return c
		}
	}

	return &firstContainer
}

func GetContainerByName(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if c.Name == name {
			return c
		}
	}

	return nil
}
