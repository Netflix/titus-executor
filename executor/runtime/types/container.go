package types

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/config"
	metadataserverTypes "github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/Netflix/titus-executor/models"
	ptr "k8s.io/utils/pointer"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

const (
	appNameLabelKey           = "com.netflix.titus.appName"
	commandLabelKey           = "com.netflix.titus.command"
	entrypointLabelKey        = "com.netflix.titus.entrypoint"
	cpuLabelKey               = "com.netflix.titus.cpu"
	iamRoleLabelKey           = "ec2.iam.role"
	memLabelKey               = "com.netflix.titus.mem"
	diskLabelKey              = "com.netflix.titus.disk"
	networkLabelKey           = "com.netflix.titus.network"
	workloadTypeLabelKey      = "com.netflix.titus.workload.type"
	ownerEmailLabelKey        = "com.netflix.titus.owner.email"
	jobTypeLabelKey           = "com.netflix.titus.job.type"
	TitusTaskInstanceIDEnvVar = "TITUS_TASK_INSTANCE_ID"

	// DefaultOciRuntime is the default oci-compliant runtime used to run system services
	DefaultOciRuntime = "runc"
)

var (
	// log uploading defaults
	defaultLogUploadThresholdTime = 6 * time.Hour
	defaultLogUploadCheckInterval = 15 * time.Minute
	defaultStdioLogCheckInterval  = 1 * time.Minute
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

func addLabels(taskID string, c Container, resources *Resources) map[string]string {
	labels := map[string]string{
		models.ExecutorPidLabel: fmt.Sprintf("%d", os.Getpid()),
		models.TaskIDLabel:      taskID,
	}

	iamRole := c.IamRole()
	if iamRole != nil {
		labels[iamRoleLabelKey] = *iamRole
	}

	labels[cpuLabelKey] = itoa(resources.CPU)
	labels[memLabelKey] = itoa(resources.Mem)
	labels[diskLabelKey] = itoa(resources.Disk)
	labels[networkLabelKey] = itoa(resources.Network)

	labels = addContainerLabels(c, labels)
	labels = addPassThroughLabels(c, labels)
	labels = addProcessLabels(c, labels)
	return labels
}

func addContainerLabels(c Container, labels map[string]string) map[string]string {
	labels[appNameLabelKey] = c.AppName()

	workloadType := StaticWorkloadType
	if c.AllowCPUBursting() {
		workloadType = BurstWorkloadType
	}

	labels[workloadTypeLabelKey] = string(workloadType)

	return labels
}

func addPassThroughLabels(c Container, labels map[string]string) map[string]string {
	ownerEmailStr := ""
	jobTypeStr := ""

	jobType := c.JobType()
	if jobType != nil {
		jobTypeStr = *jobType
	}
	email := c.OwnerEmail()
	if email != nil {
		ownerEmailStr = *email
	}

	labels[ownerEmailLabelKey] = ownerEmailStr
	labels[jobTypeLabelKey] = jobTypeStr

	return labels
}

func addProcessLabels(c Container, labels map[string]string) map[string]string {
	entryPoint, command := c.Process()
	if entryPoint != nil {
		entryPointStr := strings.Join(entryPoint[:], " ")
		labels[entrypointLabelKey] = entryPointStr
	}

	if command != nil {
		commandStr := strings.Join(command[:], " ")
		labels[commandLabelKey] = commandStr
	}

	return labels
}

func isNetworkModeIPv6Only(c Container) bool {
	if c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6Only.String() ||
		c.EffectiveNetworkMode() == titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String() {
		return true
	}
	return false
}

func populateContainerEnv(c Container, config config.Config, userEnv map[string]string) map[string]string {
	// Order goes (least priority, to highest priority:
	// -Hard coded environment variables
	// -Copied environment variables from the host
	// -Resource env variables
	// -User provided environment in POD
	// -Network Config
	// -Executor overrides

	// Hard coded (in executor config)
	env := config.GetHardcodedEnv()

	// Env copied from host
	for key, value := range config.GetEnvFromHost() {
		env[key] = value
	}

	// This variable comes early from the host, and later is overwritten
	// by other env variables injected from the control plane.
	// We save it here because it is useful to "leak" the true
	// instance ID we are running on for other infrastructure tools
	env["TITUS_HOST_EC2_INSTANCE_ID"] = env["EC2_INSTANCE_ID"]

	resources := c.Resources()
	// Resource environment variables
	env["TITUS_NUM_MEM"] = itoa(resources.Mem)
	env["TITUS_NUM_CPU"] = itoa(resources.CPU)
	env["TITUS_NUM_GPU"] = itoa(resources.GPU)
	env["TITUS_NUM_DISK"] = itoa(resources.Disk)
	env["TITUS_NUM_NETWORK_BANDWIDTH"] = itoa(resources.Network)

	cluster := c.CombinedAppStackDetails()
	env["NETFLIX_CLUSTER"] = cluster
	env["NETFLIX_STACK"] = c.JobGroupStack()
	env["NETFLIX_DETAIL"] = c.JobGroupDetail()

	var asgName string
	if seq := c.JobGroupSequence(); seq == "" {
		asgName = cluster + "-v000"
	} else {
		asgName = cluster + "-" + seq
	}
	env["NETFLIX_AUTO_SCALE_GROUP"] = asgName
	env["NETFLIX_APP"] = c.AppName()

	for key, value := range userEnv {
		env[key] = value
	}

	// These environment variables may be looked at things like sidecars and they should override user environment
	if name := c.ImageName(); name != nil {
		env["TITUS_IMAGE_NAME"] = *name
	}
	if tag := c.ImageVersion(); tag != nil {
		env["TITUS_IMAGE_TAG"] = *tag
	}
	if digest := c.ImageDigest(); digest != nil {
		env["TITUS_IMAGE_DIGEST"] = *digest
	}

	// The control plane should set this environment variable.
	// If it doesn't, we should set it. It shouldn't create
	// any problems if it is set to an "incorrect" value
	if _, ok := env["EC2_OWNER_ID"]; !ok {
		env["EC2_OWNER_ID"] = ptr.StringPtrDerefOr(c.VPCAccountID(), "")
	}

	env["TITUS_IAM_ROLE"] = ptr.StringPtrDerefOr(c.IamRole(), "")

	if config.MetatronEnabled && c.MetatronCreds() != nil {
		// When set, the metadata service will return signed identity documents suitable for bootstrapping Metatron
		env[metadataserverTypes.TitusMetatronVariableName] = True
	} else {
		env[metadataserverTypes.TitusMetatronVariableName] = False
	}

	netMode := GetHumanFriendlyNetworkMode(c.EffectiveNetworkMode())
	if netMode != "" {
		env["NETFLIX_NETWORK_MODE"] = netMode
	}
	vpcAllocation := c.VPCAllocation()
	if isNetworkModeIPv6Only(c) {
		//Maintain 127.0.0.1 for EC2_LOCAL_IPV4 even for IPv6 only lest something breaks
		env[metadataserverTypes.EC2IPv4EnvVarName] = "127.0.0.1"
	} else if a := vpcAllocation.IPV4Address(); a != nil {
		env[metadataserverTypes.EC2IPv4EnvVarName] = a.Address.Address
	}

	if a := vpcAllocation.IPV6Address(); a != nil {
		env[metadataserverTypes.EC2IPv6sEnvVarName] = a.Address.Address
		env[metadataserverTypes.NetflixIPv6EnvVarName] = a.Address.Address
		env[metadataserverTypes.NetflixIPv6sEnvVarName] = a.Address.Address
		env[metadataserverTypes.NetflixIPv6HostnameEnvVar] = computeNetflixIPv6Hostname(a.Address.Address)
	}

	if a := vpcAllocation.ElasticAddress(); a != nil {
		env[metadataserverTypes.EC2PublicIPv4EnvVarName] = a.Ip
		env[metadataserverTypes.EC2PublicIPv4sEnvVarName] = a.Ip
	}

	if a := vpcAllocation.ContainerENI(); a != nil {
		env["EC2_VPC_ID"] = a.VpcId
		env["EC2_INTERFACE_ID"] = a.NetworkInterfaceId
		env["EC2_SUBNET_ID"] = a.SubnetId
	}

	if batch := c.BatchPriority(); batch != nil {
		env["TITUS_BATCH"] = *batch
	}

	if reqIMDSToken := c.RequireIMDSToken(); reqIMDSToken != nil {
		env["TITUS_IMDS_REQUIRE_TOKEN"] = *reqIMDSToken
	}

	envOverrides := c.EnvOverrides()
	for key, value := range envOverrides {
		env[key] = value
	}

	if gpuInfo := c.GPUInfo(); gpuInfo != nil {
		for key, value := range gpuInfo.Env() {
			env[key] = value
		}
	}

	env[TitusRuntimeEnvVariableName] = c.Runtime()

	return env
}

func sortedEnv(env map[string]string) []string {
	retEnv := make([]string, 0, len(env))
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		retEnv = append(retEnv, key+"="+env[key])
	}
	return retEnv
}

// combinedAppStackDetails is a port of the combineAppStackDetails method from frigga.
// See: https://github.com/Netflix/frigga/blob/v0.17.0/src/main/java/com/netflix/frigga/NameBuilder.java
func combinedAppStackDetails(c Container) string {
	if c.JobGroupDetail() != "" {
		return fmt.Sprintf("%s-%s-%s", c.AppName(), c.JobGroupStack(), c.JobGroupDetail())
	}
	if c.JobGroupStack() != "" {
		return fmt.Sprintf("%s-%s", c.AppName(), c.JobGroupStack())
	}
	return c.AppName()
}

func isEFSID(FsID string) (bool, error) {
	matched, err := regexp.MatchString(`^fs-[0-9a-f]+$`, FsID)
	if err != nil {
		// The only type of errors that might hit this are regex compile errors
		return false, fmt.Errorf("Something went really wrong determining if '%s' is an EFS ID: %s", FsID, err)
	}
	return matched, nil
}

// GetHumanFriendlyNetworkMode uses the incoming network mode string
// and mutates it a bit to be a environment-variable safe string.
// In the unknown mode, however, we return an empty string for
// the caller to *not* set the variable
func GetHumanFriendlyNetworkMode(mode string) string {
	modeInt := titus.NetworkConfiguration_NetworkMode_value[mode]
	switch modeInt {
	case int32(titus.NetworkConfiguration_UnknownNetworkMode):
		return ""
	case int32(titus.NetworkConfiguration_Ipv4Only):
		return "IPV4_ONLY"
	case int32(titus.NetworkConfiguration_Ipv6AndIpv4):
		return "DUAL_STACK"
	case int32(titus.NetworkConfiguration_Ipv6AndIpv4Fallback):
		return "IPV6_WITH_TRANSITION"
	case int32(titus.NetworkConfiguration_Ipv6Only):
		return "IPV6_ONLY"
	default:
		return ""
	}
}

func computeNetflixIPv6Hostname(ipv6 string) string {
	sanitizedv6 := strings.ReplaceAll(ipv6, ":", "-")
	return fmt.Sprintf("ip-%s.node.netflix.net", sanitizedv6)
}
