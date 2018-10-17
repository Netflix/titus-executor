package runtime

import (
	"strconv"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, constraints *runtimeTypes.Resources, labels map[string]string, cfg config.Config) *runtimeTypes.Container {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()

	strCPU := strconv.FormatInt(constraints.CPU, 10)
	strMem := strconv.FormatInt(constraints.Mem, 10)
	strDisk := strconv.FormatUint(constraints.Disk, 10)
	strNetwork := strconv.FormatUint(uint64(networkCfgParams.GetBandwidthLimitMbps()), 10)

	env := cfg.GetNetflixEnvForTask(titusInfo, strMem, strCPU, strDisk, strNetwork)
	labels["TITUS_TASK_INSTANCE_ID"] = env["TITUS_TASK_INSTANCE_ID"]
	labels["com.netflix.titus.cpu"] = strCPU
	labels["com.netflix.titus.mem"] = strMem
	labels["com.netflix.titus.disk"] = strDisk
	labels["com.netflix.titus.network"] = strNetwork

	c := &runtimeTypes.Container{
		TaskID:             taskID,
		TitusInfo:          titusInfo,
		Resources:          constraints,
		Env:                env,
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
