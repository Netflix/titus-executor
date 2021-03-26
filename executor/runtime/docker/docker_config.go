package docker

import (
	"time"

	"gopkg.in/urfave/cli.v1"
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
	bumpTiniSchedPriority           bool
	waitForSecurityGroupLockTimeout time.Duration

	titusIsolateBlockTime   time.Duration
	enableTitusIsolateBlock bool

	networkTeardownTimeout time.Duration
}

// NewConfig generates a configuration, with a set of flags tied to it for the docker runtime
func NewConfig() (*Config, []cli.Flag) {
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
			Value:       time.Minute * 10,
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
		// Allow the usage of a realtime scheduling policy to be optional on systems that don't have it properly configured
		// by default, i.e.: docker-for-mac.
		cli.BoolTFlag{
			Name:        "titus.executor.tiniSchedPriority",
			EnvVar:      "BUMP_TINI_SCHED_PRIORITY",
			Destination: &cfg.bumpTiniSchedPriority,
			Usage: "enable a realtime scheduling priority for tini (PID=1), so it can always reap processes on contended " +
				"systems. Kernels with CONFIG_RT_GROUP_SCHED=y require all cgroups in the hierarchy to have some " +
				"cpu.rt_runtime_us allocated to each one of them",
		},
	}
	return cfg, flags
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
