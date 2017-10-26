// build +linux

package runtime

/*
#include <linux/quota.h>
#include <sys/quota.h>
#include <linux/dqblk_xfs.h>
#include <errno.h>

#include <stdio.h>

int has_project_quota_enabled(const char *special) {
        struct dqinfo dqinfo;
        int err;

        if(quotactl(QCMD(Q_GETINFO, PRJQUOTA), special, 0, (caddr_t)&dqinfo))
                return -errno;

        return 1;
}
*/
import "C"

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func hasProjectQuotasEnabled(rootDir string) bool {
	tempdir, err := ioutil.TempDir("", "docker-quota-detector")
	if err != nil {
		panic(err)
	}
	defer func() {
		if err2 := os.RemoveAll(tempdir); err2 != nil {
			log.Warning("Unable to remove tempdir: ", err2)
		}
	}()

	dev, err := makeBackingFsDev(rootDir, tempdir)
	if err != nil {
		panic(err)
	}
	val := C.has_project_quota_enabled(C.CString(dev))

	if val == 1 {
		return true
	}
	errno := syscall.Errno(-val)
	if errno != unix.ESRCH {
		log.WithField("rootDir", rootDir).Warning("Got unexpected error: ", errno)
	}
	return false
}

// Code borrowed from Moby (Docker), here: https://github.com/moby/moby/blob/1009e6a40b295187e038b67e184e9c0384d95538/daemon/graphdriver/quota/projectquota.go
// Get the backing block device of the driver home directory
// and create a block device node under the home directory
// to be used by quotactl commands
func makeBackingFsDev(home, tempdir string) (string, error) {
	var stat unix.Stat_t
	if err := unix.Stat(home, &stat); err != nil {
		return "", err
	}

	backingFsBlockDev := filepath.Join(tempdir, "backingFsBlockDev")
	if err := unix.Mknod(backingFsBlockDev, unix.S_IFBLK|0600, int(stat.Dev)); err != nil {
		return "", fmt.Errorf("Failed to mknod %s: %v", backingFsBlockDev, err)
	}

	return backingFsBlockDev, nil
}
