//go:build linux
// +build linux

package bpfloader

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"runtime"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const sizeofStructBpfInsn = 8

const (
	BPF_MAP_CREATE       = iota // nolint: golint
	BPF_MAP_LOOKUP_ELEM         // nolint: golint
	BPF_MAP_UPDATE_ELEM         // nolint: golint
	BPF_MAP_DELETE_ELEM         // nolint: golint
	BPF_MAP_GET_NEXT_KEY        // nolint: golint
	BPF_PROG_LOAD               // nolint: golint
	BPF_OBJ_PIN                 // nolint: golint
	BPF_OBJ_GET                 // nolint: golint
)

var (
	errSectionNotFound = errors.New("Section not found")
	errLicenseNotFound = errors.New("License not found")
)

// GetProgram gets an open FD for a given BPF program, given an io.Reader of a tc-compatible elf file, and the section name
func GetProgram(reader io.ReaderAt, name string) (int, error) {
	logBuf := make([]byte, 65535)
	program := netlink.BPFAttr{
		ProgType: uint32(netlink.BPF_PROG_TYPE_SCHED_CLS),
		LogBuf:   uintptr(unsafe.Pointer(&logBuf[0])), // nolint: gosec
		LogSize:  uint32(cap(logBuf) - 1),
		LogLevel: 1,
	}
	module, err := elf.NewFile(reader)
	if err != nil {
		return 0, err
	}
	section := module.Section(name)
	if section == nil {
		return 0, errSectionNotFound
	}
	data, err := section.Data()
	if err != nil {
		return 0, err
	}

	program.Insns = uintptr(unsafe.Pointer(&data[0])) // nolint: gosec
	program.InsnCnt = uint32(len(data) / sizeofStructBpfInsn)
	license, err := elfReadLicense(module)

	program.License = uintptr(unsafe.Pointer(&license[0])) // nolint: gosec
	if err != nil {
		return 0, err
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF,
		BPF_PROG_LOAD,
		uintptr(unsafe.Pointer(&program)), // nolint: gosec
		unsafe.Sizeof(program))            // nolint: gosec
	runtime.KeepAlive(data)
	runtime.KeepAlive(license)

	if errno != 0 {
		fmt.Println(string(logBuf))
		return 0, errno
	}
	return int(fd), nil
}

func elfReadLicense(file *elf.File) ([]byte, error) {
	if lsec := file.Section("license"); lsec != nil {
		data, err := lsec.Data()
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, errLicenseNotFound
}
