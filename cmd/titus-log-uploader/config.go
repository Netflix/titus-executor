package main

import (
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Netflix/titus-executor/filesystems"
)

const (
	envKeyLocalDir            = "WATCH_LOCAL_DIR"
	envKeyUploadDir           = "WATCH_UPLOAD_DIR"
	envKeyUploadRegexp        = "WATCH_UPLOAD_REGEXP"
	envKeyUploadCheckInterval = "WATCH_UPLOAD_CHECK_INTERVAL"
	envKeyUploadThresholdTime = "WATCH_UPLOAD_THRESHOLD_TIME"
	envKeyStdioCheckInterval  = "WATCH_STDIO_CHECK_INTERVAL"
	envKeyKeepFileAfterUpload = "WATCH_KEEP_FILE_AFTER_UPLOAD"

	envKeyBucketName     = "UPLOAD_BUCKET_NAME"
	envKeyPathPrefix     = "UPLOAD_PATH_PREFIX"
	envKeyTaskRole       = "UPLOAD_TASK_ROLE"
	envKeyTaskID         = "UPLOAD_TASK_ID"
	envKeyWriterRole     = "UPLOAD_WRITER_ROLE"
	envKeyUseDefaultRole = "UPLOAD_USE_DEFAULT_ROLE"
)

func mustReadStringFromEnv(envKey string) string {
	if val, ok := os.LookupEnv(envKey); ok {
		return val
	}

	logrus.WithFields(logrus.Fields{
		"variable": envKey,
		"type":     "string",
	}).Fatal("Missing required environment variable")

	return ""
}

func mustReadDurationFromEnv(envKey string) time.Duration {
	if val, ok := os.LookupEnv(envKey); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"key":   envKey,
				"value": val,
				"err":   err,
			}).Fatal("Unable to parse valid duration from environment variable")
			return 0
		}
		return dur
	}

	logrus.WithFields(logrus.Fields{
		"variable": envKey,
		"type":     "duration",
	}).Fatal("Missing required environment variable")
	return 0
}

func mustReadRegexpFromEnv(envKey string) *regexp.Regexp {
	if val, ok := os.LookupEnv(envKey); ok {
		r, err := regexp.Compile(val)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"key":   envKey,
				"value": val,
				"err":   err,
			}).Error("Unable to parse valid regular expression from environment variable")
			return nil
		}
		return r
	}

	logrus.WithFields(logrus.Fields{
		"variable": envKey,
		"type":     "regexp",
	}).Fatal("Missing required environment variable")
	return nil
}

func mustReadBoolFromEnv(envKey string) bool {
	if val, ok := os.LookupEnv(envKey); ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"key":   envKey,
				"value": val,
				"err":   err,
			}).Error("Unable to parse valid bool from environment variable")
			return false
		}
		return b
	}

	logrus.WithFields(logrus.Fields{
		"variable": envKey,
		"type":     "bool",
	}).Fatal("Missing required environment variable")
	return false
}

// titus-log-rotator is an application that extracts the job of uploading files from a specific directory to
// s3.  It expects the files to be rotated written to and rotated by an external application.

func watchConfigFromEnvironment() (filesystems.WatchConfig, error) {
	localDir := mustReadStringFromEnv(envKeyLocalDir)
	uploadDir := mustReadStringFromEnv(envKeyUploadDir)
	uploadRegexp := mustReadRegexpFromEnv(envKeyUploadRegexp)
	uploadCheckInterval := mustReadDurationFromEnv(envKeyUploadCheckInterval)
	uploadThresholdTime := mustReadDurationFromEnv(envKeyUploadThresholdTime)
	stdioLogCheckInterval := mustReadDurationFromEnv(envKeyStdioCheckInterval)
	keepFileAfterUpload := mustReadBoolFromEnv(envKeyKeepFileAfterUpload)

	return filesystems.NewWatchConfig(
		localDir,
		uploadDir,
		uploadRegexp,
		uploadCheckInterval,
		uploadThresholdTime,
		stdioLogCheckInterval,
		keepFileAfterUpload,
	), nil
}

type s3UploadConfig struct {
	bucketName     string
	pathPrefix     string
	taskRole       string
	taskID         string
	writerRole     string
	useDefaultRole bool
}

func uploadConfigFromEnvironment() (s3UploadConfig, error) {
	bucketName := mustReadStringFromEnv(envKeyBucketName)
	pathPrefix := mustReadStringFromEnv(envKeyPathPrefix)
	taskRole := mustReadStringFromEnv(envKeyTaskRole)
	taskID := mustReadStringFromEnv(envKeyTaskID)
	writerRole := mustReadStringFromEnv(envKeyWriterRole)
	useDefaultRole := mustReadBoolFromEnv(envKeyUseDefaultRole)

	return s3UploadConfig{
		bucketName:     bucketName,
		pathPrefix:     pathPrefix,
		taskRole:       taskRole,
		taskID:         taskID,
		writerRole:     writerRole,
		useDefaultRole: useDefaultRole,
	}, nil
}
