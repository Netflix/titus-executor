package main

import (
	"context"
	"github.com/Netflix/titus-executor/vk"
	"github.com/sirupsen/logrus"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	logruslogger "github.com/virtual-kubelet/virtual-kubelet/log/logrus"
	"time"
)


func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := logrus.StandardLogger()
	logger.SetLevel(logrus.DebugLevel)
	log.L = logruslogger.FromLogrus(logrus.NewEntry(logger))
	ctx = log.WithLogger(ctx, log.L)
	defer time.Sleep(1 * time.Second)


	p, err := vk.NewVk()
	if err != nil {
		log.G(ctx).WithError(err).Fatal()
	}

	err = p.Start(ctx)
	if err != nil {
		log.G(ctx).WithError(err).Fatal()
	}

}
