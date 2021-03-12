package main

import (
	"context"
	"os"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/utils/log"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ebsVolumeFlagName     = "titus-ebs-volume-id"
	taskIDFlagName        = "titus-task-id"
	ebsMountPointFlagName = "ebs-mount-point"
	ebsMountPermFlagName  = "ebs-mount-perm"
	ebsFSTypeFlagName     = "ebs-fstype"
	titusPid1DirFlagName  = "titus-pid1-dir"
)

type MountConfig struct {
	taskID        string
	pid1Dir       string
	ebsMountPoint string
	ebsMountPerm  string
	ebsFStype     string
	ebsVolumeID   string
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.MaybeSetupLoggerIfOnJournaldAvailable()
	v := viper.New()

	var cmd = &cobra.Command{
		Short:        "The container sidecar for attaching storage",
		Long:         "",
		ValidArgs:    []string{"start", "stop"},
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			mountConfig := newMountConfigFromViper(v)
			ctx = logger.WithFields(ctx, logrus.Fields{
				"ebs_volume_id": mountConfig.ebsVolumeID,
				"taskid":        mountConfig.taskID,
			})
			l := logger.GetLogger(ctx)
			command := args[0]
			l.Infof("Running titus-storage with %s", command)
			err := ebsRunner(ctx, command, mountConfig)
			if err != nil {
				l.Error(err)
			}
			return err
		},
		Use: "titus-storage <start|stop>",
	}

	if err := v.BindPFlags(cmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}

	bindVariables(v)
	v.AutomaticEnv()

	err := cmd.Execute()
	if err != nil {
		// The reason we don't log here is because it wouldn't be
		// under the structured logger object, so better to just
		// let the caller log and not print anything here.
		os.Exit(1)
	}
	os.Exit(0)
}

func bindVariables(v *viper.Viper) {
	if err := v.BindEnv(ebsVolumeFlagName, "TITUS_EBS_VOLUME_ID"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(taskIDFlagName, "TITUS_TASK_ID"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(ebsMountPointFlagName, "TITUS_EBS_MOUNT_POINT"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(ebsMountPermFlagName, "TITUS_EBS_MOUNT_PERM"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(ebsFSTypeFlagName, "TITUS_EBS_FSTYPE"); err != nil {
		panic(err)
	}
	if err := v.BindEnv(titusPid1DirFlagName, "TITUS_PID_1_DIR"); err != nil {
		panic(err)
	}

}

func newMountConfigFromViper(v *viper.Viper) MountConfig {
	return MountConfig{
		ebsVolumeID:   v.GetString(ebsVolumeFlagName),
		taskID:        v.GetString(taskIDFlagName),
		ebsMountPoint: v.GetString(ebsMountPointFlagName),
		ebsMountPerm:  v.GetString(ebsMountPermFlagName),
		ebsFStype:     v.GetString(ebsFSTypeFlagName),
		pid1Dir:       v.GetString(titusPid1DirFlagName),
	}
}
