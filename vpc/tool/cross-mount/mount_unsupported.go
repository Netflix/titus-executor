//go:build !linux
// +build !linux

package mount

import "github.com/Netflix/titus-executor/vpc/types"

func Mount(netnsfd int, where string) error {
	return types.ErrUnsupported
}
