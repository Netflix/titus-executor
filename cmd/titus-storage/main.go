package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/utils/log"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)



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
			mountConfig := newEBSMountConfigFromViper(v)
			ctx = logger.WithFields(ctx, logrus.Fields{
				"ebs_volume_id": mountConfig.ebsVolumeID,
				"taskid":        mountConfig.taskID,
			})
			l := logger.GetLogger(ctx)
			command := args[0]
			l.Infof("Running titus-storage with %s", command)
			exclusiveLock, err := getExclusiveLock(ctx)
			if err != nil {
				return err
			}
			defer exclusiveLock.Unlock()
			if mountConfig.ebsVolumeID != "" {
				err := ebsRunner(ctx, command, mountConfig)
				if err != nil {
					l.WithError(err)
					return err
				}
			}
			if ephemeralStorageIsAvailable() {
				err := ephemeralStorageRunner(ctx, command, mountConfig)
				if err != nil {
					l.WithError(err).Error("Non-fatal error when mounting ephemeral storage")
					return nil
				}
			}
			//mount cephfs, if there is no cephfs, it will be no-op
			err = mountCephFS(ctx, v)
			if err != nil {
				l.WithError(err).Error("error mounting cephFS")
				return err
			}
			return nil
		},
		Use: "titus-storage <start|stop>",
	}

	if err := v.BindPFlags(cmd.PersistentFlags()); err != nil {
		logger.G(ctx).WithError(err).Fatal("Unable to configure Viper")
	}

	bindEBSVariables(v)
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



func getExclusiveLock(ctx context.Context) (*fslocker.ExclusiveLock, error) {
	stateDir := "/run/titus-storage"
	fslockerDir := filepath.Join(stateDir, "fslocker")
	if err := os.MkdirAll(fslockerDir, 0700); err != nil {
		return nil, err
	}
	locker, err := fslocker.NewFSLocker(fslockerDir)
	if err != nil {
		return nil, err
	}
	fiveMin := 300 * time.Second
	exclusiveLock, err := locker.ExclusiveLock(ctx, utilities.GetGlobalConfigurationLock(), &fiveMin)
	if err != nil {
		return nil, err
	}
	return exclusiveLock, nil
}
