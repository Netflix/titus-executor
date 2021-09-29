//go:build !linux
// +build !linux

package mount

import "github.com/Netflix/titus-executor/vpc/types"

func Mount(fd int, where string) error {
	return types.ErrUnsupported
}
