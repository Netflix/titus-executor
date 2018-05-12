package config

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"gopkg.in/urfave/cli.v1"
)

const (
	defaultLogUploadThreshold     = 6 * time.Hour
	defaultLogUploadCheckInterval = 15 * time.Minute
	defaultStdioLogCheckInterval  = 1 * time.Minute
	defaultLogsTmpDir             = "/var/lib/titus-container-logs"
)

// Config contains the executor configuration
type Config struct { // nolint: maligned
	// MetatronEnabled returns if Metatron is enabled
	MetatronEnabled bool
	// PrivilegedContainersEnabled returns whether to give tasks CAP_SYS_ADMIN
	PrivilegedContainersEnabled bool
	// UseNewNetworkDriver returns which network driver to use
	UseNewNetworkDriver bool
	// DisableMetrics makes it so we don't send metrics to Atlas
	DisableMetrics bool
	// LogUpload returns settings about the log uploader
	//LogUpload logUpload
	LogsTmpDir string
	// Stack returns the stack configuration variable
	Stack string
	// Docker returns the Docker-specific configuration settings
	DockerHost     string
	DockerRegistry string

	KeepLocalFileAfterUpload bool
	LogUploadThresholdTime   time.Duration
	LogUploadCheckInterval   time.Duration
	StdioLogCheckInterval    time.Duration

	// CopiedFromHost indicates which environment variables to lift from the current config
	copiedFromHostEnv cli.StringSlice
	hardCodedEnv      cli.StringSlice

	CopyUploaders cli.StringSlice
	S3Uploaders   cli.StringSlice
	NoopUploaders cli.StringSlice
}

// NewConfig generates a configuration and a set of flags to passed to urfave/cli
func NewConfig() (*Config, []cli.Flag) {
	cfg := &Config{
		copiedFromHostEnv: []string{
			"NETFLIX_ENVIRONMENT",
			"NETFLIX_ACCOUNT",
			"NETFLIX_STACK",
			"EC2_INSTANCE_ID",
			"EC2_REGION",
			"EC2_AVAILABILITY_ZONE",
			"EC2_OWNER_ID",
			"EC2_VPC_ID",
			"EC2_RESERVATION_ID",
		},
		hardCodedEnv: []string{
			"NETFLIX_APPUSER=appuser",
			"EC2_DOMAIN=amazonaws.com",
		},
	}

	flags := []cli.Flag{
		cli.BoolTFlag{
			Name:        "metatron-enabled",
			EnvVar:      "METATRON_ENABLED",
			Destination: &cfg.MetatronEnabled,
		},
		cli.BoolFlag{
			Name:        "privileged-containers-enabled",
			EnvVar:      "PRIVILEGED_CONTAINERS_ENABLED",
			Destination: &cfg.PrivilegedContainersEnabled,
		},
		cli.BoolFlag{
			Name:        "use-new-network-driver",
			EnvVar:      "USE_NEW_NETWORK_DRIVER",
			Destination: &cfg.UseNewNetworkDriver,
		},
		cli.BoolFlag{
			Name:        "disable-metrics",
			EnvVar:      "DISABLE_METRICS,SHORT_CIRCUIT_QUITELITE",
			Destination: &cfg.DisableMetrics,
		},
		cli.StringFlag{
			Name:        "logs-tmp-dir",
			Value:       defaultLogsTmpDir,
			EnvVar:      "LOGS_TMP_DIR",
			Destination: &cfg.LogsTmpDir,
		},
		cli.StringFlag{
			Name:        "stack",
			Value:       "mainvpc",
			EnvVar:      "STACK,NETFLIX_STACK",
			Destination: &cfg.Stack,
		},
		cli.StringFlag{
			Name: "docker-host",
			// In prod this is tcp://127.0.0.1:4243
			Value:       "unix:///var/run/docker.sock",
			Destination: &cfg.DockerHost,
			EnvVar:      "DOCKER_HOST",
		},
		cli.StringFlag{
			Name:        "docker-registry",
			Value:       "docker.io",
			Destination: &cfg.DockerRegistry,
			EnvVar:      "DOCKER_REGISTRY",
		},
		cli.BoolFlag{
			Name:        "keep-local-file-after-upload",
			Destination: &cfg.KeepLocalFileAfterUpload,
		},
		cli.DurationFlag{
			Name:        "log-upload-threshold-time",
			Value:       defaultLogUploadThreshold,
			Destination: &cfg.LogUploadThresholdTime,
		},
		cli.DurationFlag{
			Name:        "log-upload-check-interval",
			Value:       defaultLogUploadCheckInterval,
			Destination: &cfg.LogUploadCheckInterval,
		},
		cli.DurationFlag{
			Name:        "stdio-check-interval",
			Value:       defaultStdioLogCheckInterval,
			Destination: &cfg.StdioLogCheckInterval,
		},
		cli.StringSliceFlag{
			Name:  "copied-from-host-env",
			Value: &cfg.copiedFromHostEnv,
		},
		cli.StringSliceFlag{
			Name:  "hard-coded-env",
			Value: &cfg.hardCodedEnv,
		},

		cli.StringSliceFlag{
			Name:  "s3-uploader",
			Value: &cfg.S3Uploaders,
		},
		cli.StringSliceFlag{
			Name:  "copy-uploader",
			Value: &cfg.CopyUploaders,
		},
		cli.StringSliceFlag{
			Name:  "noop-uploaders",
			Value: &cfg.NoopUploaders,
		},
	}

	return cfg, flags
}

func (c *Config) GetNetflixEnvForTask(taskInfo *titus.ContainerInfo, mem, cpu, disk, networkBandwidth string) map[string]string { // nolint: golint
	env := c.getEnvHardcoded()
	env = appendMap(env, c.getEnvFromHost())
	env = appendMap(env, c.getEnvBasedOnTask(taskInfo, mem, cpu, disk, networkBandwidth))
	env = appendMap(env, c.getUserProvided(taskInfo))
	return env
}

func (c *Config) getEnvBasedOnTask(taskInfo *titus.ContainerInfo, mem, cpu, disk, networkBandwidth string) map[string]string {
	env1 := make(map[string]string)

	c.setClusterInfoBasedOnTask(taskInfo, env1)
	env1["TITUS_NUM_MEM"] = mem
	env1["TITUS_NUM_CPU"] = cpu
	env1["TITUS_NUM_DISK"] = disk
	env1["TITUS_NUM_NETWORK_BANDWIDTH"] = networkBandwidth

	return env1
}

// Sets cluster info based on provided task info.
func (c *Config) setClusterInfoBasedOnTask(taskInfo *titus.ContainerInfo, env map[string]string) {
	// TODO(Andrew L): Remove this check once appName is required
	appName := taskInfo.GetAppName()
	if appName == "" {
		// Use image name as app name if no app name is provided.
		appName = getAppName(taskInfo.GetImageName())
	}

	cluster := combineAppStackDetails(taskInfo, appName)
	env["NETFLIX_APP"] = appName
	env["NETFLIX_CLUSTER"] = cluster
	env["NETFLIX_STACK"] = taskInfo.GetJobGroupStack()
	env["NETFLIX_DETAIL"] = taskInfo.GetJobGroupDetail()

	var asgName string
	if seq := taskInfo.GetJobGroupSequence(); seq == "" {
		asgName = cluster + "-v000"
	} else {
		asgName = cluster + "-" + seq
	}
	env["NETFLIX_AUTO_SCALE_GROUP"] = asgName
}

func (c *Config) getEnvFromHost() map[string]string {
	fromHost := make(map[string]string)

	for _, hostKey := range c.copiedFromHostEnv {
		if hostKey == "NETFLIX_STACK" {
			// Add agent's stack as TITUS_STACK so platform libraries can
			// determine agent stack, if needed
			addElementFromHost(fromHost, hostKey, "TITUS_STACK")
		} else {
			addElementFromHost(fromHost, hostKey, hostKey)
		}
	}
	return fromHost
}

func addElementFromHost(addTo map[string]string, hostEnvVarName string, containerEnvVarName string) {
	hostVal := os.Getenv(hostEnvVarName)
	if hostVal != "" {
		addTo[containerEnvVarName] = hostVal
	}
}

// Merge user and titus provided ENV vars
func (c *Config) getUserProvided(taskInfo *titus.ContainerInfo) map[string]string {
	var (
		userProvided  = taskInfo.GetUserProvidedEnv()
		titusProvided = taskInfo.GetTitusProvidedEnv()
	)
	if len(userProvided) == 0 && len(titusProvided) == 0 {
		return getUserProvidedDeprecated(taskInfo)
	}

	delete(userProvided, "") // in case users provided key=nil
	// titus provided can override user provided
	return appendMap(userProvided, titusProvided)
}

// ENV from the deprecated environmentVariable field that had both user and Titus provided values merged
func getUserProvidedDeprecated(taskInfo *titus.ContainerInfo) map[string]string {
	vars := make(map[string]string)
	for _, env := range taskInfo.GetEnvironmentVariable() {
		vars[env.GetName()] = env.GetValue()
	}
	return vars
}

// appendMap works like the builtin append function, but for maps. nil can be safely passed in.
func appendMap(m map[string]string, add map[string]string) map[string]string {
	all := make(map[string]string, len(m)+len(add))
	for k, v := range m {
		all[k] = v
	}
	for k, v := range add {
		all[k] = v
	}
	return all
}

// combineAppStackDetails is a port of the method with the same name from frigga.
// See: https://github.com/Netflix/frigga/blob/v0.17.0/src/main/java/com/netflix/frigga/NameBuilder.java
func combineAppStackDetails(taskInfo *titus.ContainerInfo, appName string) string {
	var (
		stack   = taskInfo.GetJobGroupStack()
		details = taskInfo.GetJobGroupDetail()
	)
	if details != "" {
		return fmt.Sprintf("%s-%s-%s", appName, stack, details)
	}
	if stack != "" {
		return fmt.Sprintf("%s-%s", appName, stack)
	}
	return appName
}

// TODO: This is deprecated and should be removed as soon as API is redesigned
func getAppName(imageName string) string {
	split := strings.Split(imageName, "/")
	lastWord := split[len(split)-1]
	appName := ""
	for _, runeVal := range lastWord {
		if unicode.IsLetter(runeVal) || unicode.IsDigit(runeVal) {
			appName += string(runeVal)
		} else {
			appName += "_"
		}
	}
	return appName
}

func (c *Config) getEnvHardcoded() map[string]string {
	env1 := make(map[string]string)

	for _, line := range c.hardCodedEnv {
		kv := strings.SplitN(line, "=", 2)
		env1[kv[0]] = kv[1]
	}

	return env1
}

// GenerateConfiguration is only meant to validate the behaviour of parsing command line arguments
func GenerateConfiguration(args []string) (*Config, error) {
	cfg, flags := NewConfig()

	app := cli.NewApp()
	app.Flags = flags
	app.Action = func(c *cli.Context) error {
		return nil
	}
	if args == nil {
		args = []string{}
	}

	args = append([]string{"fakename"}, args...)

	return cfg, app.Run(args)
}
