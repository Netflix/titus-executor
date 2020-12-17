package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/logviewer/api"
	"github.com/Netflix/titus-executor/logviewer/conf"
	"github.com/Netflix/titus-executor/tag"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/sirupsen/logrus"
)

/*
	This binary handles log persistence and access from within a pod.

	It accomplishes this by having an injected shared volume and a webserver.
	The binary monitors this shared volume and publishes to s3 on a specified cadience.
	Also runs a simple web server implementing the log-viewer handlers
*/

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

	logrus.WithFields(logrus.Fields{
		"watchConfig":  wconf,
		"uploadConfig": uc,
	}).Info("Booting with config")

	mux := &http.ServeMux{}
	api.RegisterHandlers(mux)
	conf.RunningInContainer = true

	server := http.Server{
		Addr:         ":8004", // TODO[cconger]: Config this port
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	s3Backend, err := uploader.NewS3Backend(
		m,
		uc.bucketName,
		uc.pathPrefix,
		uc.taskRole,
		uc.taskID,
		uc.writerRole,
		uc.useDefaultRole,
	)
	if err != nil {
		logrus.Fatal(err)
	}
	u := uploader.NewUploaderWithBackend(s3Backend)

	watcher, err := filesystems.NewWatcher(m, *wconf, u)
	if err != nil {
		logrus.Fatal(err)
	}

	err = watcher.Watch(ctx)
	if err != nil {
		logrus.Fatal(err)
	}

	// Start the logviewer webserver
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Error("Server unexpectedly failed listening")

			// Cancel context to terminate app
			cancel()
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	// Block on a signal or toplevel context cancel
	select {
	case sig := <-sigs:
		logrus.WithField("signal", sig).Warn("Received signal, shutting down")
	case <-ctx.Done():
	}

	err = watcher.Stop()
	if err != nil {
		logrus.Errorf("Error stopping watcher: %s", err)
	}
	err = server.Shutdown(ctx)
	if err != nil {
		logrus.Errorf("Error shutting down webserver: %s", err)
	}
	logrus.Info("Final upload completed")
}
