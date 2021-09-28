//go:build linux
// +build linux

package main

import (
	"context"

	"github.com/Netflix/titus-executor/logger"
	"github.com/coreos/go-systemd/daemon"
)

func notifySystemd(ctx context.Context) {
	sent, err := daemon.SdNotify(false, "READY=1")
	if err != nil {
		logger.G(ctx).WithError(err).Warning("Unable to notify systemd")
	} else if !sent {
		logger.G(ctx).Info("Systemd notification not sent")
	}
}
