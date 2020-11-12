package pod

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

const (
	// High-level "domains" used for labels and annotations
	DomainNetflix = "netflix.com"
	DomainTitus   = "titus.netflix.com"
	DomainPod     = "pod.netflix.com"

	// Job details
	LabelKeyApp      = "netflix.com/applicationName"
	LabelKeyDetail   = "netflix.com/detail"
	LabelKeySequence = "netflix.com/sequence"
	LabelKeyStack    = "netflix.com/stack"

	LabelKeyByteUnitsEnabled = "pod.titus.netflix.com/byteUnits"
	LabelKeyCapacityGroup    = "titus.netflix.com/capacityGroup"
)

// Is the control plane indicating that it's sending the resources in bytes?
func ByteUnitsEnabled(pod *corev1.Pod) (bool, error) {
	bytesEnabled, ok := pod.GetLabels()[LabelKeyByteUnitsEnabled]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(bytesEnabled)
}
