package main

import (
	"context"
	"fmt"
	"github.com/Netflix/titus-executor/logger"
	"github.com/spf13/viper"
	"os"
	"os/exec"
	"strings"
)

const (
	mountCephCommand = "/apps/titus-executor/bin/titus-mount-ceph"
)

type CephMountCommand struct {
	perms      string
	mountPoint string
	monitorIP  string
	cephFSPath string
	containerPID string
	name         string
	secret       string
}

func mountCephFS(ctx context.Context, v *viper.Viper) error {
	l := logger.GetLogger(ctx)

	cmds, err := cephMountCmds(ctx, v)
	if err != nil {
		return err
	}
	for _, mc := range cmds {
		flags, err := calculateFlags(mc.perms)
		if err != nil {
			return err
		}
		l.Printf("Running %s to mount %s onto %s in the container on monitor %s with permission %s containerPID %s",
			mountCephCommand, mc.cephFSPath, mc.mountPoint, mc.monitorIP, mc.perms, mc.containerPID)
		cmd := exec.Command(mountCephCommand, mc.containerPID)
		cmd.Env = []string{
			"MOUNT_TARGET=" + mc.mountPoint,
			"MOUNT_OPTIONS=" + cephOptions(mc),
			"MOUNT_FLAGS=" + flags,
			"MOUNT_SOURCE=" + mountSource(mc),
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		l.Printf("%s %s", strings.Join(cmd.Env, " "), mountCephCommand)
		err = cmd.Run()
		if err != nil {
			return err
		}
	}
	return nil
}

func cephOptions(mc CephMountCommand) string {
	return fmt.Sprintf("name=%s,secret=%s", mc.name, mc.secret)
}

func mountSource(mc CephMountCommand) string  {
	return fmt.Sprintf("%s:%s", mc.monitorIP, mc.cephFSPath)
}

func isMountingCephFS(mc *CephMountCommand) bool  {
	return mc != nil
}

func cephMountCmds(ctx context.Context, v *viper.Viper) ([]CephMountCommand, error) {
	cmds, err := mountCmds(ctx, CEPHFS, v.GetString(taskIDFlagName))
	if err != nil {
		return nil, err
	}
	ret := make([]CephMountCommand, 30)
	for _, c := range cmds {
		ret = append(ret, c.(CephMountCommand))
	}
	return ret, nil
}
