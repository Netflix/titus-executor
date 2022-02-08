//go:build !linux
// +build !linux

package inject

import "context"

func Inject(ctx context.Context, pid1dir string, subsequentExe []string) error {
	panic("Unsupported")
}
