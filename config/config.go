package config

import (
	"os"
	"strings"

	"gopkg.in/urfave/cli.v1"
)

const (
	defaultLogsTmpDir = "/var/lib/titus-container-logs"
)

// Config contains the executor configuration
type Config struct {
	// nolint: maligned

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

	// MetatronEnabled returns if Metatron is enabled
	MetatronEnabled      bool
	MetatronServiceImage string

	// Enable an in-container logviewer via a volume container?
	ContainerLogViewer    bool
	LogViewerServiceImage string

	// Enable abmetrix service
	ContainerAbmetrixEnabled bool
	AbmetrixServiceImage     string

	// Enable an in-container system mesh image?
	ContainerServiceMeshEnabled bool
	ProxydServiceImage          string

	// Do we enable a container-specific SSHD?
	ContainerSSHD    bool
	SSHDServiceImage string

	ContainerSSHDCAFile string
	ContainerSSHDUsers  cli.StringSlice
	SSHAccountID        string

	// Do we enable spectator rootless image?
	ContainerSpectatord    bool
	SpectatordServiceImage string

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
			"EC2_REGION",
			"EC2_AVAILABILITY_ZONE",
			"EC2_OWNER_ID",
			"EC2_RESERVATION_ID",
		},
		hardCodedEnv: []string{
			"NETFLIX_APPUSER=appuser",
			"EC2_DOMAIN=amazonaws.com",
			/* See:
			 * - https://docs.aws.amazon.com/cli/latest/topic/config-vars.html
			 * - https://github.com/jtblin/kube2iam/issues/31
			 * AWS_METADATA_SERVICE_TIMEOUT, and AWS_METADATA_SERVICE_NUM_ATTEMPTS are respected by all AWS standard SDKs
			 * as timeouts for connecting to the metadata service.
			 */
			"AWS_METADATA_SERVICE_TIMEOUT=5",
			"AWS_METADATA_SERVICE_NUM_ATTEMPTS=3",
			"EC2_INSTANCE_ID=i-mock",
		},
		ContainerSSHDUsers: []string{
			"root",
			"nfsuper",
			"nfbasic",
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
		cli.StringFlag{
			Name:        "metatron-service-image",
			Destination: &cfg.MetatronServiceImage,
			EnvVar:      "METATRON_SERVICE_IMAGE",
		},
		cli.BoolTFlag{
			Name:        "container-logviewer",
			Destination: &cfg.ContainerLogViewer,
			EnvVar:      "CONTAINER_LOGVIEWER",
		},
		cli.StringFlag{
			Name:        "logviewer-service-image",
			Destination: &cfg.LogViewerServiceImage,
			EnvVar:      "LOGVIEWER_SERVICE_IMAGE",
		},
		cli.BoolTFlag{
			Name:        "container-abmetrix",
			Destination: &cfg.ContainerAbmetrixEnabled,
			EnvVar:      "CONTAINER_ABMETRIX",
		},
		cli.StringFlag{
			Name:        "abmetrix-service-image",
			Destination: &cfg.AbmetrixServiceImage,
			EnvVar:      "ABMETRIX_SERVICE_IMAGE",
		},
		cli.BoolFlag{
			Name:        "container-servicemesh-enabled",
			EnvVar:      "CONTAINER_SERVICEMESH_ENABLED",
			Destination: &cfg.ContainerServiceMeshEnabled,
		},
		cli.StringFlag{
			Name:        "proxyd-service-image",
			Destination: &cfg.ProxydServiceImage,
			EnvVar:      "PROXYD_SERVICE_IMAGE",
		},
		cli.BoolTFlag{
			Name:        "container-sshd",
			Destination: &cfg.ContainerSSHD,
			EnvVar:      "CONTAINER_SSHD",
		},
		cli.StringFlag{
			Name:        "sshd-service-image",
			Destination: &cfg.SSHDServiceImage,
			EnvVar:      "SSHD_SERVICE_IMAGE",
		},
		cli.StringFlag{
			Name:        "container-sshd-ca-file",
			Value:       "/etc/ssh/titus_user_ssh_key_cas.pub",
			Destination: &cfg.ContainerSSHDCAFile,
			EnvVar:      "CONTAINER_SSHD_CA_FILE",
		},
		cli.StringSliceFlag{
			Name:  "container-sshd-users",
			Value: &cfg.ContainerSSHDUsers,
		},
		cli.StringFlag{
			Name:        "ssh-account-id",
			Destination: &cfg.SSHAccountID,
			EnvVar:      "SSH_ACCOUNT_ID",
		},
		cli.BoolFlag{
			Name:        "container-spectatord",
			EnvVar:      "CONTAINER_SPECTATORD",
			Destination: &cfg.ContainerSpectatord,
		},
		cli.StringFlag{
			Name:        "container-spectatord-image",
			EnvVar:      "SPECTATORD_SERVICE_IMAGE",
			Destination: &cfg.SpectatordServiceImage,
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

func (c *Config) GetEnvFromHost() map[string]string {
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

func (c *Config) GetHardcodedEnv() map[string]string {
	env := make(map[string]string)

	for _, line := range c.hardCodedEnv {
		kv := strings.SplitN(line, "=", 2)
		env[kv[0]] = kv[1]
	}

	return env
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
