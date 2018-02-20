package main

import (
	"os"
	"time"

	"github.com/Netflix/titus-executor/vpc/allocate"
	"github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/gc"
	"github.com/Netflix/titus-executor/vpc/globalgc"
	"github.com/Netflix/titus-executor/vpc/setup"
	"gopkg.in/urfave/cli.v1"
)

// TODO: Add Systemd loggin

func main() {
	app := cli.NewApp()
	app.Name = "titus-vpc-tool"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   context.StateDir,
			Value:  "/run/titus-vpc-tool",
			Usage:  "Where to store the state, and locker state -- creates directory",
			EnvVar: "VPC_STATE_DIR",
		},
		cli.StringFlag{
			Name:  "log-level",
			Value: "info",
		},
		cli.BoolTFlag{
			Name:  "journald",
			Usage: "Allows disabling the journald logging hook -- is enabled by default",
		},
	}
	app.Commands = []cli.Command{
		setup.Setup,
		allocate.AllocateNetwork,
		gc.GC,
		allocate.SetupContainer,
		globalgc.GlobalGC,
	}

	// This is here because logs are buffered, and it's a way to try to guarantee that logs
	// are flushed at shutdown
	defer time.Sleep(100 * time.Millisecond)
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
