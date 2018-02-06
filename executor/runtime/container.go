package runtime

import (
	"strconv"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
)

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, constraints *runtimeTypes.Resources, labels map[string]string) *runtimeTypes.Container {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()
	env := config.GetNetflixEnvForTask(titusInfo,
		strconv.FormatInt(constraints.Mem, 10),
		strconv.FormatInt(constraints.CPU, 10),
		strconv.FormatUint(constraints.Disk, 10),
	)
	labels["TITUS_TASK_INSTANCE_ID"] = env["TITUS_TASK_INSTANCE_ID"]

	c := &runtimeTypes.Container{
		TaskID:             taskID,
		TitusInfo:          titusInfo,
		Resources:          constraints,
		Env:                env,
		Labels:             labels,
		SecurityGroupIDs:   networkCfgParams.GetSecurityGroups(),
		BandwidthLimitMbps: networkCfgParams.GetBandwidthLimitMbps(),
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
