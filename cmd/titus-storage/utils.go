package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Netflix/titus-executor/cmd/common"
	"github.com/Netflix/titus-executor/logger"
	docker "github.com/docker/docker/client"
	corev1 "k8s.io/api/core/v1"
)

func calculateFlags(mountPerm string) (string, error) {
	if mountPerm == "RW" {
		return "0", nil
	} else if mountPerm == "RO" {
		return "1", nil
	}
	return "", fmt.Errorf("error parsing the mount permissions: '%s', needs to be only RW/RO", mountPerm)
}

const CEPHFS = "CEPHFS"

func mountCmds(ctx context.Context, mtype string, taskId string) ([]interface{}, error) {
	l := logger.GetLogger(ctx)
	dockerClient, err := docker.NewClient("unix:///var/run/docker.sock", "1.26", nil, map[string]string{})
	if err != nil {
		return nil, err
	}
	defer dockerClient.Close()

	pod, err := common.ReadTaskPodFile(taskId)
	if err != nil {
		return nil, err
	}
	containerNameToId := make(map[string]string)
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ContainerID != "" {
			containerNameToId[cs.Name] = cs.ContainerID
		}
	}
	l.Printf("container name  to id map %v", containerNameToId)
	var cmds []interface{}
	for _, p := range pod.Spec.Volumes {
		switch mtype {
		case CEPHFS:
			if p.CephFS != nil {
				mountDetail := containersUsingVolume(p.Name, pod)
				mons := strings.Join(p.CephFS.Monitors, ",")
				cephFSPath := p.CephFS.Path
				user := p.CephFS.User
				secret := p.CephFS.SecretFile
				perms := "RW"
				if p.CephFS.ReadOnly {
					perms = "R"
				}
				for _, d := range mountDetail {
					containerId := containerNameToId[d.containerName]
					l.Printf("getting pid for container %s containerId %s ", d.containerName, containerId)
					inspect, err := dockerClient.ContainerInspect(ctx, containerId)
					if err != nil {
						return nil, err
					}
					containerPID := strconv.Itoa(inspect.State.Pid)
					l.Printf("pid for container %s", containerPID)
					cmd := CephMountCommand{
						perms:        perms,
						mountPoint:   d.mountPath,
						monitorIP:    mons,
						cephFSPath:   cephFSPath,
						containerPID: containerPID,
						name:         user,
						secret:       secret,
					}
					cmds = append(cmds, cmd)
					l.Printf("add mount cmd %v", cmd)
				}
			}
		default:
			return nil, nil
		}
	}
	return cmds, nil
}

type ContainerVolumeMount struct {
	mountPath     string
	containerName string
}

func containersUsingVolume(vol string, pod *corev1.Pod) []ContainerVolumeMount {
	var ret []ContainerVolumeMount
	for _, c := range pod.Spec.Containers {
		for _, v := range c.VolumeMounts {
			if v.Name == vol {
				ret = append(ret, ContainerVolumeMount{
					mountPath:     v.MountPath,
					containerName: c.Name,
				})
			}
		}
	}
	return ret
}
