// +build !linux

package main

import k8sMount "k8s.io/utils/mount"

func listProcMounts() ([]k8sMount.MountPoint, error) {
	return nil, nil
}
