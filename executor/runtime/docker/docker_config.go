package docker

import (
	"os"
	"path/filepath"
	"time"

	"github.com/urfave/cli"
)

// Config represents the configuration for the Docker titus runtime
type Config struct { // nolint: maligned
	cfsBandwidthPeriod              uint64
	tiniVerbosity                   int
	burst                           bool
	nvidiaOciRuntime                string
	pidLimit                        int
	prepareTimeout                  time.Duration
	startTimeout                    time.Duration
	tiniPath                        string
	waitForSecurityGroupLockTimeout time.Duration

	titusIsolateBlockTime   time.Duration
	enableTitusIsolateBlock bool

	networkTeardownTimeout time.Duration
}

// NewConfig generates a configuration, with a set of flags tied to it for the docker runtime
func NewConfig() (*Config, []cli.Flag) {
	defaultTiniPath := getTiniDefaultPath()
	cfg := &Config{}
	flags := []cli.Flag{
		cli.DurationFlag{
			Name:        "titus.executor.networkTeardownTimeout",
			EnvVar:      "NETWORK_TEARDOWN_TIMEOUT",
			Value:       time.Second * 30,
			Destination: &cfg.networkTeardownTimeout,
		},
		cli.Uint64Flag{
			Name:        "titus.executor.cfsBandwidthPeriod",
			EnvVar:      "CFS_BANDWIDTH_PERIOD",
			Value:       100000,
			Destination: &cfg.cfsBandwidthPeriod,
		},
		cli.IntFlag{
			Name:        "titus.executor.tiniVerbosity",
			Value:       0,
			Destination: &cfg.tiniVerbosity,
		},
		cli.BoolFlag{
			Name:        "titus.executor.networking.burst",
			Destination: &cfg.burst,
		},
		cli.StringFlag{
			Name: "titus.executor.nvidiaOciRuntime",
			// runc-compliant OCI runtime that's capable of running the `nvidia-container-runtime` hook.
			// Defaults to https://github.com/Netflix-Skunkworks/oci-add-hooks to avoid running a patched
			// version of runc, though https://github.com/NVIDIA/nvidia-container-runtime should also work.
			Value:       "oci-add-hooks",
			Destination: &cfg.nvidiaOciRuntime,
			EnvVar:      "NVIDIA_OCI_RUNTIME",
		},
		cli.IntFlag{
			Name:        "titus.executor.pidLimit",
			Value:       100000,
			Destination: &cfg.pidLimit,
		},
		cli.DurationFlag{
			Name:        "titus.executor.timeouts.prepare",
			Value:       time.Minute * 15,
			Destination: &cfg.prepareTimeout,
		},
		cli.DurationFlag{
			Name:        "titus.executor.timeouts.start",
			Value:       time.Minute * 10,
			Destination: &cfg.startTimeout,
		},
		cli.DurationFlag{
			Name:        "titus.executor.waitForSecurityGroupLockTimeout",
			Value:       time.Minute * 1,
			Destination: &cfg.waitForSecurityGroupLockTimeout,
		},
		cli.DurationFlag{
			Name:   "titus.executor.titusIsolateBlockTime",
			EnvVar: "TITUS_EXECUTOR_TITUS_ISOLATE_BLOCK_TIME",
			// The default value inside of the Titus Isolate code is 10 seconds.
			// we can wait longer than it
			Value:       30 * time.Second,
			Destination: &cfg.titusIsolateBlockTime,
		},
		cli.BoolFlag{
			Name:        "titus.executor.enableTitusIsolateBlock",
			EnvVar:      "ENABLE_TITUS_ISOLATE_BLOCK",
			Destination: &cfg.enableTitusIsolateBlock,
		},
		cli.StringFlag{
			Name:        "titus.executor.tiniPath",
			EnvVar:      "TITUS_EXECUTOR_TINI_PATH",
			Destination: &cfg.tiniPath,
			Usage:       "Location of the tini binary. Defaults to be 'tini-static' in the same location as the titus-executor binary",
			Value:       defaultTiniPath,
		},
	}

	return cfg, flags
}

func getTiniDefaultPath() string {
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	return dir + "/tini-static"
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
