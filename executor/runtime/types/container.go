package types

import (
	"strconv"
	"strings"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
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

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, resources *Resources, labels map[string]string, cfg config.Config) *Container {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()

	strCPU := strconv.FormatInt(resources.CPU, 10)
	strMem := strconv.FormatInt(resources.Mem, 10)
	strDisk := strconv.FormatUint(resources.Disk, 10)
	strNetwork := strconv.FormatUint(resources.Network, 10)

	env := cfg.GetNetflixEnvForTask(titusInfo, strMem, strCPU, strDisk, strNetwork)
	// System service systemd units need this to be set in order to run with the right runtime path
	env[TitusRuntimeEnvVariableName] = DefaultOciRuntime
	labels[titusTaskInstanceIDKey] = env[titusTaskInstanceIDKey]
	labels[cpuLabelKey] = strCPU
	labels[memLabelKey] = strMem
	labels[diskLabelKey] = strDisk
	labels[networkLabelKey] = strNetwork
	addLabels(titusInfo, labels)

	c := &Container{
		TaskID:             taskID,
		TitusInfo:          titusInfo,
		Resources:          resources,
		Env:                env,
		Labels:             labels,
		SecurityGroupIDs:   networkCfgParams.GetSecurityGroups(),
		BandwidthLimitMbps: resources.Network,
		Config:             cfg,
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

	return c
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
