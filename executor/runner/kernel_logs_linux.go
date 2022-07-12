//go:build linux
// +build linux

package runner

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/sirupsen/logrus"
)

var errNotTitusTask = fmt.Errorf("Not a titus task")

var cgroupTaskIDRegex = regexp.MustCompile("titus-executor@default__([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}).service")

func findTitusTaskIDFromPid(pid int) (string, error) {
	cgroups, err := cgroups.ParseCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	// pick a representative cgroup, say cpuset
	root, ok := cgroups["cpuset"]
	if !ok {
		// "" is unified, which is all that's present in full v2
		root = cgroups[""]
	}

	matches := cgroupTaskIDRegex.FindStringSubmatch(root)
	if len(matches) != 2 {
		return "", errNotTitusTask
	}

	return matches[1], nil
}

var stuckTaskKernelLogLineRegex = regexp.MustCompile(`INFO: task ([\w-]+):(\d+) blocked for more than \d+ seconds`)

func parseBlockedTaskKernelLogLine(log logrus.FieldLogger, line string, myTaskID string) {
	matches := stuckTaskKernelLogLineRegex.FindStringSubmatch(line)
	if len(matches) == 0 {
		return
	}

	if len(matches) != 3 {
		log.Errorf("didn't understand regex match %v for %v", matches, line)
		return
	}

	name := matches[1]
	pid, err := strconv.Atoi(matches[2])
	if err != nil {
		log.Errorf("strange pid value in %s: %s", line, matches[2])
		return
	}

	pidsTaskID, err := findTitusTaskIDFromPid(pid)
	if err != nil {
		// maybe the task died between when we got this message and
		// when we tried to access the cgroup file.
		if os.IsNotExist(err) {
			return
		}

		// maybe this wasn't a titus task, and something on the host is locked up? punt for now.
		if err == errNotTitusTask {
			return
		}

		log.Errorf("error getting titus task from pid: %v", err)
		return
	}

	// this is somebody else's task
	if myTaskID != pidsTaskID {
		return
	}

	log.Infof("Process %d (%s) in %s hung for the task timeout length", pid, name, myTaskID)
}
