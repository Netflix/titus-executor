//go:build !linux
// +build !linux

package main

func makeMountRShared(path string) error {
	return nil
}
