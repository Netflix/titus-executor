package runtime

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Netflix/quitelite-client-go/properties"
	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/config"
	"github.com/Netflix/titus-executor/executor/metatron"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	log "github.com/sirupsen/logrus"
)

var (
	userNamespacesExemptApplications = properties.NewDynamicProperty(context.TODO(), "titus.executor.userNamespacesExemptApplications", "", "", nil)
)

func isAppInList(c *Container, dp *properties.DynamicProperty) bool {
	if c.TitusInfo.AppName != nil {
		appName := strings.TrimSpace(*c.TitusInfo.AppName)

		appNames, err := dp.Read().AsString()
		if err != nil {
			log.Warning("Unable to parse app name list: ", err)
		}
		for _, exemptApp := range strings.Split(appNames, ",") {
			if strings.TrimSpace(exemptApp) == appName {
				return true
			}
		}
	} else {
		log.Warning("Container appname unset: ", c)
	}
	return false
}

type cleanupFunc func() error

// Container contains config state for a container.
// It is not safe to be used concurrently, synchronization and locking needs to be handled externally.
type Container struct { // nolint: maligned
	ID        string
	Pid       int
	TaskID    string
	Env       map[string]string
	Labels    map[string]string
	Ports     []string
	TitusInfo *titus.ContainerInfo
	Resources *Resources

	userNamespacesDisabled bool

	// Metatron fields
	MetatronConfig *metatron.CredentialsConfig

	// cleanup callbacks that runtime implementations can register to do cleanup
	// after a launchGuard on the taskID has been lifted
	cleanup []cleanupFunc

	// VPC driver fields
	SecurityGroupIDs []string
	// Titus Index 1 = ENI index 0
	Allocation         vpcTypes.Allocation
	NormalizedENIIndex int
	BandwidthLimitMbps uint32

	AllocationCommand *exec.Cmd
	SetupCommand      *exec.Cmd
}

// Resources specify constraints to be applied to a Container
type Resources struct {
	Mem       int64 // in MiB
	CPU       int64
	Disk      uint64
	HostPorts []uint16
}

// NewContainer allocates and initializes a new container struct object
func NewContainer(taskID string, titusInfo *titus.ContainerInfo, constraints *Resources, labels map[string]string) *Container {
	networkCfgParams := titusInfo.GetNetworkConfigInfo()
	env := config.GetNetflixEnvForTask(titusInfo,
		strconv.FormatInt(constraints.Mem, 10),
		strconv.FormatInt(constraints.CPU, 10),
		strconv.FormatUint(constraints.Disk, 10),
	)
	labels["TITUS_TASK_INSTANCE_ID"] = env["TITUS_TASK_INSTANCE_ID"]

	c := &Container{
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

	if isAppInList(c, userNamespacesExemptApplications) {
		log.Infof("Disabling user namespaces for app %s because of app-specific fast property", c.TitusInfo.AppName)
		c.userNamespacesDisabled = true
	}

	return c
}

// QualifiedImageName appends the registry and version to the Image name
func (c *Container) QualifiedImageName() string {
	if c == nil {
		return ""
	}
	image := c.TitusInfo.GetImageName()
	baseRef := config.Docker().Registry + "/" + image
	if digest := c.TitusInfo.GetImageDigest(); digest != "" {
		// digest has precedence
		return baseRef + "@" + digest
	}
	return baseRef + ":" + c.TitusInfo.GetVersion()
}

func (c *Container) registerRuntimeCleanup(callback cleanupFunc) {
	c.cleanup = append(c.cleanup, callback)
}

// runtimeCleanup runs cleanup callbacks registered by runtime implementations
func (c *Container) runtimeCleanup() []error {
	var errs []error
	for idx := range c.cleanup {
		fn := c.cleanup[len(c.cleanup)-idx-1]
		if err := fn(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// ImageTagForMetrics returns a map with the image name
func (c *Container) ImageTagForMetrics() map[string]string {
	return map[string]string{"image": *c.TitusInfo.ImageName}
}

// UploadDir hold files that will by uploaded by log uploaders
func (c *Container) UploadDir(namespace string) string {
	return filepath.Join("titan", config.Stack(), namespace, c.TaskID)
}
