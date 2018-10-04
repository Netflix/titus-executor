package docker

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/urfave/cli.v1"
)

const minCfsBandwidth = 1000
const maxCfsBandwidth = 1000000

// Config represents the configuration for the Docker titus runtime
type Config struct { // nolint: maligned
	userNamespaceFDEnabled          bool
	cfsBandwidthPeriod              uint64
	tiniVerbosity                   int
	batchSize                       int
	burst                           bool
	securityConvergenceTimeout      time.Duration
	pidLimit                        int
	prepareTimeout                  time.Duration
	startTimeout                    time.Duration
	bumpTiniSchedPriority           bool
	waitForSecurityGroupLockTimeout time.Duration
	ipRefreshTimeout                time.Duration
}

// NewConfig generates a configuration, with a set of flags tied to it for the docker runtime
func NewConfig() (*Config, []cli.Flag) {
	cfg := &Config{}
	flags := []cli.Flag{
		cli.BoolTFlag{
			Name:        "titus.executor.userNamespacesFDEnabled",
			Destination: &cfg.userNamespaceFDEnabled,
		},
		cli.Uint64Flag{
			Name:        "titus.executor.cfsBandwidthPeriod",
			Value:       100000,
			Destination: &cfg.cfsBandwidthPeriod,
		},
		cli.IntFlag{
			Name:        "titus.executor.tiniVerbosity",
			Value:       0,
			Destination: &cfg.tiniVerbosity,
		},
		cli.IntFlag{
			Name:        "titus.executor.networking.batchSize",
			Value:       4,
			Destination: &cfg.batchSize,
		},
		cli.BoolFlag{
			Name:        "titus.executor.networking.burst",
			Destination: &cfg.burst,
		},
		cli.DurationFlag{
			Name:        "titus.executor.networking.securityConvergenceTimeout",
			Destination: &cfg.securityConvergenceTimeout,
			Value:       time.Second * 10,
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
			Name:        "titus.executor.networking.ipRefreshTimeout",
			Destination: &cfg.ipRefreshTimeout,
			Value:       time.Second * 10,
		},
		// Allow the usage of a realtime scheduling policy to be optional on systems that don't have it properly configured
		// by default, i.e.: docker-for-mac.
		cli.BoolTFlag{
			Name:        "titus.executor.tiniSchedPriority",
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

func validate(dockerCfg *Config) error {
	var bandWidthPeriod = dockerCfg.cfsBandwidthPeriod

	if bandWidthPeriod < minCfsBandwidth || bandWidthPeriod > maxCfsBandwidth {
		log.WithField("titus.executor.cfsBandwidthPeriod", bandWidthPeriod).WithField("min", minCfsBandwidth).WithField("max", maxCfsBandwidth).Error("CFS bandwidth period exceeds required bounds.")
		return errors.New("invalid CFS bandwidth period")
	}

	return nil
}
