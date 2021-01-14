// +build linux

package cni

import (
	"errors"
	"os"
	"path/filepath"
)

const namespacePath string = "/var/run/pods/"

func NSAliasPath(podName string) string {
	return filepath.Join(namespacePath, "netns-"+podName)
}

func createNetNSAlias(podName string, netnsPath string) error {
	aliasPath := NSAliasPath(podName)
	err := os.Symlink(netnsPath, aliasPath)

	if errors.Is(err, os.ErrNotExist) {
		// Create base dir if missing
		err := os.MkdirAll(filepath.Dir(aliasPath), 0755)
		if err != nil {
			return err
		}
		return os.Symlink(netnsPath, aliasPath)
	}

	return nil
}

func deleteNetNSAlias(podName string) error {
	err := os.Remove(NSAliasPath(podName))
	if errors.Is(err, os.ErrNotExist) {
		// No fail if the file is already gone
		return nil
	}
	return err
}
