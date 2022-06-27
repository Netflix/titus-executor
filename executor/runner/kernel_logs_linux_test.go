//go:build linux
// +build linux

package runner

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestHungTaskIDParsing(t *testing.T) {
	assert := assert.New(t)

	const fakeTaskID = "9c97e413-77bb-4953-8232-2ea03f43d36c"
	const fakeTitusService = "titus-executor@default__" + fakeTaskID + ".service"

	cpusetPath := "/"
	cpusetMountpoint := "/sys/fs/cgroup/cpuset"
	mounts, err := cgroups.GetCgroupMounts(true)
	assert.NoError(err)
	for _, m := range mounts {
		for _, controller := range m.Subsystems {
			if controller == "cpuset" {
				cpusetPath = m.Root
				cpusetMountpoint = m.Mountpoint
				break
			}
		}
	}

	fakeServiceCgroupPath := path.Join(cpusetMountpoint, cpusetPath, fakeTitusService)
	if err := os.MkdirAll(fakeServiceCgroupPath, 0755); err != nil {
		if os.IsPermission(err) {
			t.Skipf("couldn't create cgroup paths due to insufficient perms")
		}
		assert.NoError(err)
	}
	defer cgroups.RemovePath(fakeServiceCgroupPath) // nolint: errcheck

	script := fmt.Sprintf(`#!/bin/bash -exu
cgroup_path=%s
echo 0 > "${cgroup_path}/cpuset.cpus"
echo 0 > "${cgroup_path}/cpuset.mems"
echo $$ > "${cgroup_path}/tasks"
sleep 100
`, fakeServiceCgroupPath)

	f, err := ioutil.TempFile("", "kernel-logs-test-")
	assert.NoError(err)
	f.Close()
	defer os.RemoveAll(f.Name()) // nolint: errcheck

	err = ioutil.WriteFile(f.Name(), []byte(script), 0000)
	assert.NoError(err)

	assert.NoError(os.Chmod(f.Name(), 0555))
	cmd := exec.Command(f.Name()) // nolint: gosec
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	assert.NoError(cmd.Start())
	defer cmd.Process.Kill() // nolint: errcheck

	// wait for the task to set up its cgroups. if it times out we'll
	// assert below anyway, so no need to check errors.
	for i := 0; i < 3; i++ {
		taskID, _ := findTitusTaskIDFromPid(cmd.Process.Pid)
		if taskID != "" {
			break
		}
		time.Sleep(1 * time.Second)
	}

	buf := &bytes.Buffer{}

	formatter := new(logrus.TextFormatter)
	formatter.DisableTimestamp = true
	formatter.DisableLevelTruncation = true

	l := &logrus.Logger{
		Out:       buf,
		Formatter: formatter,
		Level:     logrus.DebugLevel,
	}

	parseBlockedTaskKernelLogLine(l, fmt.Sprintf("INFO: task fake:%d blocked for more than 42 seconds", cmd.Process.Pid), fakeTaskID)
	assert.NoError(err)
	assert.Equal(fmt.Sprintf("level=info msg=\"Process %d (fake) in %s hung for the task timeout length\"\n", cmd.Process.Pid, fakeTaskID), buf.String())
}
