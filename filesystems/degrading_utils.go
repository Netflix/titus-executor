package filesystems

import (
	"bytes"
	"errors"
	"os"
	"syscall"
	"unsafe"

	"runtime"

	log "github.com/sirupsen/logrus"
)

const maxValueSize = 4 * 1024 * 1024 // 4MB
const unusedArg = 0

// ssize_t is variable across systems, but on ours it's int64, we use the same name as the system for consistency
type ssize_t int64 // nolint: golint

// ErrInvalidKey is returned when a key is 0 bytes, or otherwise considered as invalid
var ErrInvalidKey = errors.New("Key Invalid")
var listXattrsStartBufferSize = 16 * 1024 // 16KB buffer to start with

func makeHole(file *os.File, start, len int64) error {
	return realMakeHole(file, start, len)
}

func fRealListXattrs(file *os.File, bufsize int) (map[string]struct{}, error) {
	buf := make([]byte, bufsize)
	// The second argument seems to catch RDX? which isn't part of the OS X calling convention as far as I can tell
	const options = 0
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_FLISTXATTR, file.Fd(), pointerToByteSlice(buf), uintptr(len(buf)), options, unusedArg, unusedArg)
	runtime.KeepAlive(buf)
	ret := ssize_t(tmpRet)
	if ret == -1 {
		if err == syscall.ERANGE {
			log.Debugf("Buffer %d too small for file attributes", bufsize)
			if bufsize <= 4*1024*1024 { // Give up if there are more than 4MB of keys
				log.Debug("Retrying fetching attributes")
				// Recursion: retry
				return fRealListXattrs(file, bufsize*2)
			}
		}
		return nil, err
	}
	retmap := map[string]struct{}{}

	for _, key := range bytes.Split(buf[:ret], []byte{0}) {
		if len(key) > 0 {
			retmap[string(key)] = struct{}{}
		}
	}

	return retmap, nil
}

func fListXattrs(file *os.File) (map[string]struct{}, error) {
	return fRealListXattrs(file, listXattrsStartBufferSize)
}

func fSetXattr(file *os.File, key string, value []byte) error {
	if len(key) == 0 {
		return ErrInvalidKey
	}
	byteKey := append([]byte(key), 0)
	return realFSetXattr(file, byteKey, value)
}

func fDelXattr(file *os.File, key string) error {
	if len(key) == 0 {
		return ErrInvalidKey
	}
	byteKey := append([]byte(key), 0)
	return realFDelXattr(file, byteKey)
}

func fGetXattr(file *os.File, key string) ([]byte, error) {
	byteKey := append([]byte(key), 0)
	return realFGetXattr(file, byteKey)
}

func realListXattrs(path []byte, bufsize int) (map[string]struct{}, error) {
	buf := make([]byte, bufsize)
	// The second argument seems to catch RDX? which isn't part of the OS X calling convention as far as I can tell
	const options = 0
	tmpRet, _, err := syscall.RawSyscall6(syscall.SYS_LISTXATTR, pointerToByteSlice(path), pointerToByteSlice(buf), uintptr(len(buf)), options, unusedArg, unusedArg)
	ret := ssize_t(tmpRet)
	if ret == -1 {
		if err == syscall.ERANGE {
			log.Debugf("Buffer %d too small for file attributes", bufsize)
			if bufsize <= 4*1024*1024 { // Give up if there are more than 4MB of keys
				log.Debug("Retrying fetching attributes")
				// Recursion: retry
				return realListXattrs(path, bufsize*2)
			}
		}
		return nil, err
	}
	retmap := map[string]struct{}{}

	for _, key := range bytes.Split(buf[:ret], []byte{0}) {
		if len(key) > 0 {
			retmap[string(key)] = struct{}{}
		}
	}
	// Otherwise the pointer might get garbage collected
	runtime.KeepAlive(buf)

	return retmap, nil
}

// ListXattrs returns a set of all of the xattrs on a file
func ListXattrs(path string) (map[string]struct{}, error) {

	return realListXattrs(append([]byte(path), 0), listXattrsStartBufferSize)
}

// SetXattr sets, or overwrites a key-value attribute pair for the given filename
func SetXattr(path string, key string, value []byte) error {
	if len(key) == 0 {
		return ErrInvalidKey
	}
	byteKey := append([]byte(key), 0)
	return realSetXattr(append([]byte(path), 0), byteKey, value)
}

func delXattr(path string, key string) error { // nolint: deadcode
	if len(key) == 0 {
		return ErrInvalidKey
	}
	byteKey := append([]byte(key), 0)
	return realDelXattr(append([]byte(path), 0), byteKey)
}

func getXattr(path string, key string) ([]byte, error) {
	byteKey := append([]byte(key), 0)
	return realGetXattr(append([]byte(path), 0), byteKey)
}

func pointerToByteSlice(byteSlice []byte) uintptr {
	if len(byteSlice) == 0 {
		// If the byte slice is 0 bytes, we should never allow it to be dereferenced
		return 0
	}
	// Use of unsafe calls should be audited,LOW,HIGH (gas)
	return uintptr(unsafe.Pointer(&byteSlice[0])) // nolint: gas
}
