package types

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/aws/aws-sdk-go/aws/arn"
	corev1 "k8s.io/api/core/v1"
)

const (
	appNameLabelKey          = "com.netflix.titus.appName"
	commandLabelKey          = "com.netflix.titus.command"
	entrypointLabelKey       = "com.netflix.titus.entrypoint"
	cpuLabelKey              = "com.netflix.titus.cpu"
	memLabelKey              = "com.netflix.titus.mem"
	diskLabelKey             = "com.netflix.titus.disk"
	networkLabelKey          = "com.netflix.titus.network"
	workloadTypeLabelKey     = "com.netflix.titus.workload.type"
	ownerEmailLabelKey       = "com.netflix.titus.owner.email"
	ownerEmailPassThroughKey = "titus.agent.ownerEmail"
	jobTypeLabelKey          = "com.netflix.titus.job.type"
	jobTypePassThroughKey    = "titus.agent.jobType"
	titusTaskInstanceIDKey   = "TITUS_TASK_INSTANCE_ID"
)

// WorkloadType classifies isolation behaviors on resources (e.g. CPU).  The exact implementation details of the
// isolation mechanism are determine by an isolation service (e.g. titus-isolate).
type WorkloadType string

// Regardless of isolation mechanism:
//
//     "static" workloads are provided resources which to the greatest degree possible are isolated from other workloads
//     on a given host.  In return they opt out of the opportunity to consume unused resources opportunistically.
//
//     "burst" workloads opt in to consumption of unused resources on a host at the cost of accepting the possibility of
//     more resource interference from other workloads.
const (
	StaticWorkloadType WorkloadType = "static"
	BurstWorkloadType  WorkloadType = "burst"
)

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, resources Resources, labels map[string]string, cfg config.Config) (*Container, error) {
	return NewContainerWithPod(taskID, titusInfo, resources, labels, cfg, nil)
}

// NewContainer allocates and initializes a new container struct object. Pod can be optionally passed. If nil, ignored
func NewContainerWithPod(taskID string, titusInfo *titus.ContainerInfo, resources Resources, labels map[string]string, cfg config.Config, pod *corev1.Pod) (*Container, error) {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()

	labels[cpuLabelKey] = itoa(resources.CPU)
	labels[memLabelKey] = itoa(resources.Mem)
	labels[diskLabelKey] = itoa(resources.Disk)
	labels[networkLabelKey] = itoa(resources.Network)
	addLabels(titusInfo, labels)

	c := &Container{
		TaskID:             taskID,
		TitusInfo:          titusInfo,
		Resources:          resources,
		envOverrides:       map[string]string{},
		Labels:             labels,
		SecurityGroupIDs:   networkCfgParams.GetSecurityGroups(),
		BandwidthLimitMbps: resources.Network,
		Config:             cfg,
		runtime:            DefaultOciRuntime,
	}
	if pod != nil {
		if l := len(pod.Spec.Containers); l != 1 {
			return nil, fmt.Errorf("Pod has unexpected number of containers (not 1): %d", l)
		}
		c.pod = pod.DeepCopy()
	}

	if eniLabel := networkCfgParams.GetEniLabel(); eniLabel != "" {
		titusENIIndex, err := strconv.Atoi(networkCfgParams.GetEniLabel())
		if err != nil {
			panic(err)
		}
		// Titus uses the same indexes as the EC2 device id
		// Titus Index 1 = ENI index 0
		c.NormalizedENIIndex = titusENIIndex + 1
	}

	if titusInfo.SignedAddressAllocation != nil {
		c.AllocationUUID = titusInfo.SignedAddressAllocation.AddressAllocation.Uuid
	}

	c.Labels[titusTaskInstanceIDKey] = c.GetEnv()[titusTaskInstanceIDKey]

	c.iamRole = c.TitusInfo.GetIamProfile()

	if c.iamRole == "" {
		return nil, ErrMissingIAMRole
	}

	if _, err := arn.Parse(c.iamRole); err != nil {
		return nil, fmt.Errorf("Could not parse iam profile %q, due to %w", c.iamRole, err)
	}

	return c, nil
}

func addLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	labels = addContainerLabels(containerInfo, labels)
	labels = addPassThroughLabels(containerInfo, labels)
	labels = addProcessLabels(containerInfo, labels)
	return labels
}

func addContainerLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	labels[appNameLabelKey] = containerInfo.GetAppName()

	workloadType := StaticWorkloadType
	if containerInfo.GetAllowCpuBursting() {
		workloadType = BurstWorkloadType
	}

	labels[workloadTypeLabelKey] = string(workloadType)

	return labels
}

func addPassThroughLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	ownerEmail := ""
	jobType := ""

	passthroughAttributes := containerInfo.GetPassthroughAttributes()
	if passthroughAttributes != nil {
		ownerEmail = passthroughAttributes[ownerEmailPassThroughKey]
		jobType = passthroughAttributes[jobTypePassThroughKey]
	}

	labels[ownerEmailLabelKey] = ownerEmail
	labels[jobTypeLabelKey] = jobType

	return labels
}

func addProcessLabels(containerInfo *titus.ContainerInfo, labels map[string]string) map[string]string {
	process := containerInfo.GetProcess()
	if process != nil {
		entryPoint := process.GetEntrypoint()
		if entryPoint != nil {
			entryPointStr := strings.Join(entryPoint[:], " ")
			labels[entrypointLabelKey] = entryPointStr
		}

		command := process.GetCommand()
		if command != nil {
			commandStr := strings.Join(entryPoint[:], " ")
			labels[commandLabelKey] = commandStr
		}
	}

	return labels
}
