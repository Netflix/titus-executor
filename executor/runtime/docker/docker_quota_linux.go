// build +linux

package docker

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"runtime"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

/*
struct dqinfo
  {
    __uint64_t dqi_bgrace;
    __uint64_t dqi_igrace;
    __uint32_t dqi_flags;
    __uint32_t dqi_valid;
  };
*/

const q_getinfo = 0x800005 // nolint
const prjquota = 2

const subcmdshift = 8
const subcmdmask = 0x00ff

type dqinfo struct { // nolint
	dqi_bgrace uint64 // nolint
	dqi_igrace uint64 // nolint
	dqi_flags  uint32 // nolint
	dqi_valid  uint32 // nolint
}

func qcmd(_cmd, _type int) int {
	return (((_cmd) << subcmdshift) | ((_type) & subcmdmask))
}

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

	var dqi dqinfo

	devcstr := []byte(dev + "\x00")                        // This is to cast it into a cstr
	devcstrPointer := uintptr(unsafe.Pointer(&devcstr[0])) // nolint: gas
	dqiPointer := uintptr(unsafe.Pointer(&dqi))            // nolint: gas

	r1, _, errno := syscall.Syscall6(syscall.SYS_QUOTACTL, uintptr(qcmd(q_getinfo, prjquota)), devcstrPointer, 0, dqiPointer, 0, 0)

	runtime.KeepAlive(devcstr)
	runtime.KeepAlive(dqi)

	if errno == syscall.Errno(0) && int(r1) != -1 {
		return true
	}

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
