package main

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/Netflix/titus-executor/filesystems"
)

// ErrorMissingEnvVariable is a error type for reporting a missing environment variable.
type ErrorMissingEnvVariable struct {
	Key string
}

func (e *ErrorMissingEnvVariable) Error() string {
	return fmt.Sprintf("missing environment variable %s", e.Key)
}

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

func readStringFromEnv(envKey string) (string, error) {
	if val, ok := os.LookupEnv(envKey); ok {
		return val, nil
	}

	return "", &ErrorMissingEnvVariable{Key: envKey}
}

func readDurationFromEnv(envKey string) (time.Duration, error) {
	if val, ok := os.LookupEnv(envKey); ok {
		dur, err := time.ParseDuration(val)
		if err != nil {
			return 0, fmt.Errorf("parsing time %s from %s: %w", val, envKey, err)
		}
		return dur, nil
	}

	return 0, &ErrorMissingEnvVariable{Key: envKey}
}

func readRegexpFromEnv(envKey string) (*regexp.Regexp, error) {
	if val, ok := os.LookupEnv(envKey); ok {
		r, err := regexp.Compile(val)
		if err != nil {
			return nil, fmt.Errorf("parsing regular expression %s from %s: %w", val, envKey, err)
		}
		return r, nil
	}

	return nil, &ErrorMissingEnvVariable{Key: envKey}
}

func readBoolFromEnv(envKey string) (bool, error) {
	if val, ok := os.LookupEnv(envKey); ok {
		b, err := strconv.ParseBool(val)
		if err != nil {
			return false, fmt.Errorf("paring bool %s from %s: %w", val, envKey, err)
		}
		return b, nil
	}

	return false, &ErrorMissingEnvVariable{Key: envKey}
}

func watchConfigFromEnvironment() (*filesystems.WatchConfig, error) {
	localDir, err := readStringFromEnv(envKeyLocalDir)
	if err != nil {
		return nil, err
	}
	uploadDir, err := readStringFromEnv(envKeyUploadDir)
	if err != nil {
		return nil, err
	}
	uploadRegexp, err := readRegexpFromEnv(envKeyUploadRegexp)
	if err != nil {
		return nil, err
	}
	uploadCheckInterval, err := readDurationFromEnv(envKeyUploadCheckInterval)
	if err != nil {
		return nil, err
	}
	uploadThresholdTime, err := readDurationFromEnv(envKeyUploadThresholdTime)
	if err != nil {
		return nil, err
	}
	stdioLogCheckInterval, err := readDurationFromEnv(envKeyStdioCheckInterval)
	if err != nil {
		return nil, err
	}
	keepFileAfterUpload, err := readBoolFromEnv(envKeyKeepFileAfterUpload)
	if err != nil {
		return nil, err
	}

	config := filesystems.NewWatchConfig(
		localDir,
		uploadDir,
		uploadRegexp,
		uploadCheckInterval,
		uploadThresholdTime,
		stdioLogCheckInterval,
		keepFileAfterUpload,
	)
	return &config, nil
}

type s3UploadConfig struct {
	bucketName     string
	pathPrefix     string
	taskRole       string
	taskID         string
	writerRole     string
	useDefaultRole bool
}

func uploadConfigFromEnvironment() (*s3UploadConfig, error) {
	bucketName, err := readStringFromEnv(envKeyBucketName)
	if err != nil {
		return nil, err
	}
	pathPrefix, err := readStringFromEnv(envKeyPathPrefix)
	if err != nil {
		return nil, err
	}
	taskRole, err := readStringFromEnv(envKeyTaskRole)
	if err != nil {
		return nil, err
	}
	taskID, err := readStringFromEnv(envKeyTaskID)
	if err != nil {
		return nil, err
	}
	writerRole, err := readStringFromEnv(envKeyWriterRole)
	if err != nil {
		return nil, err
	}
	useDefaultRole, err := readBoolFromEnv(envKeyUseDefaultRole)
	if err != nil {
		return nil, err
	}

	return &s3UploadConfig{
		bucketName:     bucketName,
		pathPrefix:     pathPrefix,
		taskRole:       taskRole,
		taskID:         taskID,
		writerRole:     writerRole,
		useDefaultRole: useDefaultRole,
	}, nil
}
