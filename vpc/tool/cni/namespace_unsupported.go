// +build !linux

package cni

import (
	"github.com/Netflix/titus-executor/vpc/types"
)

func NSAliasPath(podName string) string {
	return ""
}

func createNetNSAlias(podName string, netnsPath string) error {
	return types.ErrUnsupported
}

func deleteNetNSAlias(podName string) error {
	return types.ErrUnsupported
}
