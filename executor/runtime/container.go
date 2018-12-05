package runtime

import (
	"strconv"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

const (
	cpuLabelKey            = "com.netflix.titus.cpu"
	memLabelKey            = "com.netflix.titus.mem"
	diskLabelKey           = "com.netflix.titus.disk"
	networkLabelKey        = "com.netflix.titus.network"
	workloadTypeLabelKey   = "com.netflix.titus.workload.type"
	titusTaskInstanceIDKey = "TITUS_TASK_INSTANCE_ID"
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
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, resources *runtimeTypes.Resources, labels map[string]string, cfg config.Config) *runtimeTypes.Container {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()

	strCPU := strconv.FormatInt(resources.CPU, 10)
	strMem := strconv.FormatInt(resources.Mem, 10)
	strDisk := strconv.FormatUint(resources.Disk, 10)
	strNetwork := strconv.FormatUint(uint64(networkCfgParams.GetBandwidthLimitMbps()), 10)

	env := cfg.GetNetflixEnvForTask(titusInfo, strMem, strCPU, strDisk, strNetwork)
	labels[titusTaskInstanceIDKey] = env[titusTaskInstanceIDKey]
	labels[cpuLabelKey] = strCPU
	labels[memLabelKey] = strMem
	labels[diskLabelKey] = strDisk
	labels[networkLabelKey] = strNetwork

	workloadType := StaticWorkloadType
	if titusInfo.GetAllowCpuBursting() {
		workloadType = BurstWorkloadType
	}

	labels[workloadTypeLabelKey] = string(workloadType)

	c := &runtimeTypes.Container{
		TaskID:             taskID,
		TitusInfo:          titusInfo,
		Resources:          resources,
		Env:                env,
		IsSystemD:          false,
		Labels:             labels,
		SecurityGroupIDs:   networkCfgParams.GetSecurityGroups(),
		BandwidthLimitMbps: networkCfgParams.GetBandwidthLimitMbps(),
		Config:             cfg,
	}
	if eniLabel := networkCfgParams.GetEniLabel(); eniLabel != "" {
		titusENIIndex, err := strconv.Atoi(networkCfgParams.GetEniLabel())
		if err != nil {
			panic(err)
		}
		c.NormalizedENIIndex = titusENIIndex + 1
	}

	return c
}
