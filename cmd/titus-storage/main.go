package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/Netflix/titus-executor/cmd/common"
	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/utils/log"
	"github.com/Netflix/titus-executor/vpc/utilities"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
)

const (
	ebsVolumeFlagName     = "titus-ebs-volume-id"
	taskIDFlagName        = "titus-task-id"
	ebsMountPointFlagName = "ebs-mount-point"
	ebsMountPermFlagName  = "ebs-mount-perm"
	ebsFSTypeFlagName     = "ebs-fstype"
	titusPid1DirFlagName  = "titus-pid1-dir"
	start                 = "start"
	stop                  = "stop"
	// These mount attributes should be used with the newer mount syscalls:
	// https://sourcegraph.com/github.com/torvalds/linux@01f856ae6d0ca5ad0505b79bf2d22d7ca439b2a1/-/blob/include/uapi/linux/mount.h?L131
	// And should not be confused with the MS_* flags used by the classic mount syscall.
	MOUNT_ATTR_RDONLY  = 1          // nolint: golint
	MOUNT_ATTR_NOATIME = 0x00000010 // nolint: golint
)

type MountConfig struct {
	taskID        string
	pid1Dir       string
	ebsMountPoint string
	ebsMountPerm  string
	ebsFStype     string
	ebsVolumeID   string
	pod           *corev1.Pod
}

func main() {
	go common.HandleQuitSignal()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.MaybeSetupLoggerIfOnJournaldAvailable()
	v := viper.New()

	var cmd = &cobra.Command{
		Short:        "The container sidecar for attaching storage",
		Long:         "",
		ValidArgs:    []string{start, stop},
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
			pod, err := common.ReadTaskPodFile(mountConfig.taskID)
			if err != nil {
				l.WithError(err).Error("Error when reading pod.json file")
				return err
			}

			// Setup NFS volume mounts on all containers.
			if err := setupNFSMounts(ctx, mountConfig.taskID, pod); err != nil {
				l.WithError(err).Error("Error when mounting NFS volumes")
				return err
			}

			mountConfig.pod = pod
			// Currently only doing mntShared on multi-container workloads
			if len(pod.Spec.Containers) > 1 {
				err = mntSharedRunner(ctx, command, mountConfig)
				if err != nil {
					l.WithError(err).Error("Error setting up /mnt-shared")
					return err
				}
			} else {
				l.Info("Not a multi-container workload, not doing shared")
			}
			err = sharedVolumeSourceRunner(ctx, command, mountConfig)
			if err != nil {
				l.WithError(err).Error("Error setting up shared volumes between containers")
				return err
			}
			err = lustreRunner(ctx, command, mountConfig)
			if err != nil {
				l.WithError(err).Error("Error setting up lustre volumes")
				return err
			}
			err = emptyDirRunner(ctx, command, mountConfig)
			if err != nil {
				l.WithError(err).Error("Error setting up emptyDir volumes")
				return err
			}
			if mountConfig.ebsVolumeID != "" {
				exclusiveLock, err := getExclusiveLock(ctx)
				if err != nil {
					l.WithError(err).Error("Error getting a lock on the host for EBS mounting")
					return err
				}
				defer exclusiveLock.Unlock()
				err = ebsRunner(ctx, command, mountConfig)
				if err != nil {
					l.WithError(err).Error("Error mounting EBS for the pod")
					return err
				}
			}
			return nil
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
