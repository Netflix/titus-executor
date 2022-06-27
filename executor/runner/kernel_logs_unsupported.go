//go:build !linux
// +build !linux

package runner

import (
	"github.com/sirupsen/logrus"
)

func parseBlockedTaskKernelLogLine(log logrus.FieldLogger, line string, myTaskID string) {

}
