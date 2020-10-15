package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/sirupsen/logrus"

	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/tag"
	"github.com/Netflix/titus-executor/uploader"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := metrics.New(ctx, logrus.StandardLogger(), tag.Defaults)

	wconf, err := watchConfigFromEnvironment()
	if err != nil {
		logrus.Fatal(err)
	}

	uc, err := uploadConfigFromEnvironment()
	if err != nil {
		logrus.Fatal(err)
	}

	s3Backend, err := uploader.NewS3Backend(m, uc.bucketName, uc.pathPrefix, uc.taskRole, uc.taskID, uc.writerRole, uc.useDefaultRole)
	if err != nil {
		logrus.Fatal(err)
	}
	u := uploader.NewUploaderWithBackend(s3Backend)

	watcher, err := filesystems.NewWatcher(m, wconf, u)
	if err != nil {
		logrus.Fatal(err)
	}

	err = watcher.Watch(ctx)
	if err != nil {
		logrus.Fatal(err)
	}

	// TODO[cconger]: Trap SIGTERM and wait until we write all remaining logs before closing.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	// Block on a signal
	sig := <-sigs
	watcher.Stop()
	logrus.WithFields(logrus.Fields{
		"signal": sig,
	}).Warn("Received signal, shutting down")
}
