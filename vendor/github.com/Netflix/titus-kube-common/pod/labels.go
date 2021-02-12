package pod

import (
	"fmt"
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

const (
	// High-level "domains" used for labels and annotations
	DomainNetflix = "netflix.com"
	DomainTitus   = "titus.netflix.com"
	DomainPod     = "pod.netflix.com"

	// Job details
	LabelKeyAppLegacy      = "netflix.com/applicationName"
	LabelKeyDetailLegacy   = "netflix.com/detail"
	LabelKeySequenceLegacy = "netflix.com/sequence"
	LabelKeyStackLegacy    = "netflix.com/stack"

	LabelKeyByteUnitsEnabled    = "pod.titus.netflix.com/byteUnits"
	LabelKeyCapacityGroupLegacy = "titus.netflix.com/capacityGroup"

	// v1 pod labels
	LabelKeyJobId         = "v3.job.titus.netflix.com/job-id"
	LabelKeyTaskId        = "v3.job.titus.netflix.com/task-id"
	LabelKeyAppName       = "app.netflix.com/name"
	LabelKeyAppStack      = "app.netflix.com/stack"
	LabelKeyAppDetail     = "app.netflix.com/detail"
	LabelKeyAppSequence   = "app.netflix.com/sequence"
	LabelKeyCapacityGroup = "titus.netflix.com/capacity-group"
)

// Is the control plane indicating that it's sending the resources in bytes?
func ByteUnitsEnabled(pod *corev1.Pod) (bool, error) {
	bytesEnabled, ok := pod.GetLabels()[LabelKeyByteUnitsEnabled]
	if !ok {
		return false, nil
	}

	return strconv.ParseBool(bytesEnabled)
}

func parseLabels(pod *corev1.Pod, pConf *Config) error {
	labels := pod.GetLabels()

	// Only parse the labels that aren't duplicates of annotations
	cVal, ok := labels[LabelKeyCapacityGroup]
	if ok {
		pConf.CapacityGroup = &cVal
	}

	// Maybe pull this from the containers in the pod instead?
	tVal, ok := labels[LabelKeyTaskId]
	if ok {
		pConf.TaskID = &tVal
	}

	bytesEnabledStr, ok := pod.GetLabels()[LabelKeyByteUnitsEnabled]
	if ok {
		val, err := strconv.ParseBool(bytesEnabledStr)
		if err != nil {
			return fmt.Errorf("label is not a valid boolean value: %s", LabelKeyByteUnitsEnabled)
		}
		pConf.BytesEnabled = &val
	}

	return nil
}
