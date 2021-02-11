package pod

import (
	"errors"
	"regexp"
	"time"

	resourceCommon "github.com/Netflix/titus-kube-common/resource"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// Config contains configuration parameters parsed out from various places in the pod
// (such as annotations). All fields are pointers, to differentiate between a field being
// unset and the empty value.
type Config struct {
	AssignIPv6Address      *bool
	AccountID              *string
	AppArmorProfile        *string
	AppDetail              *string
	AppName                *string
	AppMetadata            *string
	AppMetadataSig         *string
	AppOwnerEmail          *string
	AppSequence            *string
	AppStack               *string
	BytesEnabled           *bool
	CapacityGroup          *string
	CPUBurstingEnabled     *bool
	ContainerInfo          *string
	EgressBandwidth        *resource.Quantity
	ElasticIPPool          *string
	ElasticIPs             *string
	FuseEnabled            *bool
	HostnameStyle          *string
	IAMRole                *string
	IngressBandwidth       *resource.Quantity
	IMDSRequireToken       *string
	JobAcceptedTimestampMs *uint64
	JobDescriptor          *string
	JobID                  *string
	JobType                *string
	JumboFramesEnabled     *bool
	KvmEnabled             *bool
	LogKeepLocalFile       *bool
	LogUploadCheckInterval *time.Duration
	LogUploadThresholdTime *time.Duration
	LogUploadRegExp        *regexp.Regexp
	LogStdioCheckInterval  *time.Duration
	LogS3WriterIAMRole     *string
	LogS3BucketName        *string
	LogS3PathPrefix        *string
	NetworkBurstingEnabled *bool
	OomScoreAdj            *int32
	PodSchemaVersion       *uint32
	ResourceCPU            *resource.Quantity
	ResourceDisk           *resource.Quantity
	ResourceGPU            *resource.Quantity
	ResourceMemory         *resource.Quantity
	ResourceNetwork        *resource.Quantity
	SchedPolicy            *string
	SecurityGroupIDs       *[]string
	ServiceMeshEnabled     *bool
	ServiceMeshImage       *string
	StaticIPAllocation     *string
	SubnetIDs              *string
	TaskID                 *string
	TTYEnabled             *bool
}

// PodToConfig pulls out values from a pod and turns them into a Config
func PodToConfig(pod *corev1.Pod) (*Config, error) {
	pConf := &Config{}

	err := parseAnnotations(pod, pConf)
	if err != nil {
		return pConf, err
	}

	err = parseLabels(pod, pConf)
	if err != nil {
		return pConf, err
	}

	err = parsePodFields(pod, pConf)
	if err != nil {
		return pConf, err
	}

	return pConf, err
}

func getWorkloadContainer(pod *corev1.Pod, pconf *Config) *corev1.Container {
	workloadContainer := pod.Spec.Containers[0]
	if pconf.TaskID == nil {
		return &workloadContainer
	}

	// Find the container named after the task ID
	for _, c := range pod.Spec.Containers {
		if c.Name == *pconf.TaskID {
			ctrPtr := &c
			return ctrPtr
		}
	}

	return &workloadContainer
}

func parsePodFields(pod *corev1.Pod, pConf *Config) error {
	workloadContainer := getWorkloadContainer(pod, pConf)
	if workloadContainer == nil {
		return errors.New("could not find workload container in pod")
	}

	resources := workloadContainer.Resources.Limits
	pConf.ResourceCPU = resourcePtr(resources, corev1.ResourceCPU)
	pConf.ResourceDisk = resourcePtr(resources, corev1.ResourceEphemeralStorage)
	pConf.ResourceGPU = resourcePtr(resources, resourceCommon.ResourceNameGpu)
	pConf.ResourceMemory = resourcePtr(resources, corev1.ResourceMemory)
	pConf.ResourceNetwork = resourcePtr(resources, resourceCommon.ResourceNameNetwork)
	// XXX: do we need the legacy gpu and network resource names, too?

	if workloadContainer.TTY {
		ttyEnabled := true
		pConf.TTYEnabled = &ttyEnabled
	}

	return nil
}

func resourcePtr(resources corev1.ResourceList, resName corev1.ResourceName) *resource.Quantity {
	res, ok := resources[resName]
	if !ok {
		return nil
	}

	return &res
}
