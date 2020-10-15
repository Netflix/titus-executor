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
	defaultLocalDir            = "/var/log"
	defaultUploadDir           = "."
	defaultUploadCheckInterval = 15 * time.Minute
	defaultUploadThresholdTime = 6 * time.Hour
	defaultStdioCheckInterval  = 1 * time.Minute
	defaultKeepFileAfterUpload = true

	defaultBucketName     = ""
	defaultPathPrefix     = ""
	defaultTaskRole       = ""
	defaultTaskID         = ""
	defaultWriterRole     = ""
	defaultUseDefaultRole = true
)

var (
	defaultUploadRegexp *regexp.Regexp = nil
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

func readStringFromEnv(envKey string, defaultValue string) string {
	if val, ok := os.LookupEnv(envKey); ok {
		return val
	}
	return defaultValue
}

func readDurationFromEnv(envKey string, defaultValue time.Duration) time.Duration {
	if val, ok := os.LookupEnv(envKey); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"key":     envKey,
				"value":   val,
				"default": defaultValue,
				"err":     err,
			}).Error("Unable to parse valid duration from key, using default")
			return defaultValue
		}
		return dur
	}
	return defaultValue
}

func readRegexpFromEnv(envKey string, defaultValue *regexp.Regexp) *regexp.Regexp {
	if val, ok := os.LookupEnv(envKey); ok {
		r, err := regexp.Compile(val)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"key":     envKey,
				"value":   val,
				"default": defaultValue,
				"err":     err,
			}).Error("Unable to parse valid regexp from key, using default")
			return defaultValue
		}
		return r
	}
	return defaultValue
}

func readBoolFromEnv(envKey string, defaultValue bool) bool {
	if val, ok := os.LookupEnv(envKey); ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"key":     envKey,
				"value":   val,
				"default": defaultValue,
				"err":     err,
			}).Error("Unable to parse valid boolean from key, using default")
			return defaultValue
		}
		return b
	}
	return defaultValue
}

// titus-log-rotator is an application that extracts the job of uploading files from a specific directory to
// s3.  It expects the files to be rotated written to and rotated by an external application.

func watchConfigFromEnvironment() (filesystems.WatchConfig, error) {
	localDir := readStringFromEnv(envKeyLocalDir, defaultLocalDir)
	uploadDir := readStringFromEnv(envKeyUploadDir, defaultUploadDir)
	uploadRegexp := readRegexpFromEnv(envKeyUploadRegexp, defaultUploadRegexp)
	uploadCheckInterval := readDurationFromEnv(envKeyUploadCheckInterval, defaultUploadCheckInterval)
	uploadThresholdTime := readDurationFromEnv(envKeyUploadThresholdTime, defaultUploadThresholdTime)
	stdioLogCheckInterval := readDurationFromEnv(envKeyStdioCheckInterval, defaultStdioCheckInterval)
	keepFileAfterUpload := readBoolFromEnv(envKeyKeepFileAfterUpload, defaultKeepFileAfterUpload)

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
	bucketName := readStringFromEnv(envKeyBucketName, defaultBucketName)
	pathPrefix := readStringFromEnv(envKeyPathPrefix, defaultPathPrefix)
	taskRole := readStringFromEnv(envKeyTaskRole, defaultTaskRole)
	taskID := readStringFromEnv(envKeyTaskID, defaultTaskID)
	writerRole := readStringFromEnv(envKeyWriterRole, defaultWriterRole)
	useDefaultRole := readBoolFromEnv(envKeyUseDefaultRole, defaultUseDefaultRole)

	return s3UploadConfig{
		bucketName:     bucketName,
		pathPrefix:     pathPrefix,
		taskRole:       taskRole,
		taskID:         taskID,
		writerRole:     writerRole,
		useDefaultRole: useDefaultRole,
	}, nil
}
