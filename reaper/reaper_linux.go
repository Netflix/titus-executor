//go:build linux
// +build linux

package reaper

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
	"github.com/sirupsen/logrus"
)

// there is a kernel bug described in:
// https://lore.kernel.org/all/YrShFXRLtRt6T%2Fj+@risky/ where fuse can cause a
// pidns exit to deadlock. They symptoms are:
//
//    1. pidns pid 1 in S (sleeping) state
//    2. that pid has zap_pid_ns_processes() in its /proc/pid/stack
//    3. some fuse mount exists, and one of the threads from that fuse mount is
//       stuck in fuse's request_wait_answer()
//
// if those conditions are true, we need to manually tear down the fuse
// connection so the pidns can exit and docker doesn't get stuck. we can do
// this by writing something to
//
// 	/sys/fs/fuse/connections/$dev_minor/abort
//
// where $dev_minor is the minor number from the fuse superblock mount.
func checkIfFuseWedgedPidNs(pid int, taskID string) {
	if !kernelStackHas(pid, "zap_pid_ns_processes") {
		return
	}
	logrus.Debugf("found wedged pidns %d %s", pid, taskID)

	// the kernel has already destroyed the mountinfo for the pidns' init,
	// since it is pretty far along in do_exit(). we need to keep the tid
	// of the fuse process around so we can inspect its mountinfo instead.
	//
	// ideally we'd use the pids cgroup (i.e. the docker API) here to
	// figure out what tasks we should look at, but that *also* has been
	// invalidated and is incorrect at this point. luckily for us the fuse
	// daemon that's causing this hang in our production case is a child of
	// init, so we can just look at that.
	targetTid := 0
	for _, tid := range directChildThreadsOfPid(pid) {
		logrus.Debugf("checking %d for request_wait_answer", tid)
		if kernelStackHas(tid, "request_wait_answer") {
			targetTid = tid
			break
		}
	}
	if targetTid == 0 {
		logrus.Infof("wedged pid ns %s %d has no fuse tasks?", taskID, pid)
		return
	}

	// walk the mountinfo for the container and get the superblock minor
	// number. let's just manually kill any existing fuse thing, since the
	// pid ns is dying anyway.
	infos, err := mountinfo.PidMountInfo(targetTid) // nolint: staticcheck
	if err != nil {
		logrus.Errorf("failed getting mount info for %d: %v", targetTid, err)
		return
	}

	for _, m := range infos {
		if !strings.HasPrefix(m.FSType, "fuse") {
			continue
		}

		// we don't want to kill the global lxcfs fuse mount, since
		// it's a bind mount
		if strings.Contains(m.FSType, "lxcfs") {
			logrus.Debugf("skipping lxcfs mount %d in wedged task %s", m.Minor, taskID)
			continue
		}

		logrus.Infof("reaping task %s because %s is wedged. fuse minor is: %d", taskID, m.FSType, m.Minor)
		// this is fairly crude: if there are bind mounts of a fuse
		// around, we'll try to kill it multiple times. let's allow
		// ENOENT, since we might have previously killed it.
		err = ioutil.WriteFile(fmt.Sprintf("/sys/fs/fuse/connections/%d/abort", m.Minor), []byte("foo"), 0600)
		if err != nil && os.IsNotExist(err) {
			logrus.Errorf("failed killing fuse connection %d: %v", m.Minor, err)
		}
	}
}

func kernelStackHas(pid int, function string) bool {
	content, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stack", pid))
	if err != nil {
		logrus.Errorf("couldn't read kernel stack file for %d: %v", pid, err)
		return false
	}

	// the format of this file has changed somewhat over time; here's a
	// reasonable guess at e.g.
	//      [<0>] vfs_read+0x9c/0x1a0
	return strings.Contains(string(content), function+"+0x")
}

func directChildThreadsOfPid(pid int) []int {
	// "children" doesn't exist in /proc/pid for some reason...
	//
	// also note that `man proc` is wrong about this field, it only gives pids, not tids.
	threadsRaw, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		logrus.Errorf("couldn't read task dir for %d: %v", pid, err)
		return nil
	}

	threads := []int{}
	for _, e := range strings.Fields(string(threadsRaw)) {
		child, err := strconv.Atoi(e)
		if err != nil {
			logrus.Errorf("bad child for %d: %s %v", pid, e, err)
			continue
		}

		ents, err := ioutil.ReadDir(fmt.Sprintf("/proc/%d/task", child))
		if err != nil {
			logrus.Errorf("couldn't read threads for %d: %v", child, err)
			continue
		}
		for _, ent := range ents {
			tid, err := strconv.Atoi(ent.Name())
			if err != nil {
				logrus.Errorf("bad thread for %d: %s %v", child, ent.Name(), err)
				continue
			}
			threads = append(threads, tid)
		}
	}

	return threads
}
