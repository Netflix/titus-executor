package filelogger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// Logs to logdir
// Current logfile is basename.log
// when the file reaches the max file size, it is renamed to basename_Year_Month_Day_Hour_Minute_Second_Micros.log

const logFileNameFormat = "2006_01_02_15_04_05.000"
const logTimeStampFormat = "2006/01/02 15:04:05.000000"

type clock func() time.Time

type fileSystemHook struct {
	sync.Mutex
	logDir       string
	baseName     string
	extension    string
	maxFileSize  int64
	currentFile  *os.File
	formatter    logrus.Formatter
	stderrLogger *logrus.Logger
	currentSize  int64
	now          clock
}

// Initialize Installs Logrus hook for file logger -- Does not modify the default output file
func Initialize(logDir, baseName, extension string, maxFileSize int64) {
	logrus.AddHook(NewHook(logDir, baseName, extension, maxFileSize, time.Now))
}

func newStderrLogger() *logrus.Logger {
	logger := logrus.New()

	// Log everything that goes into this logger -- It's only used by the filelogger itself
	// and used to prevent cycles.
	logger.Level = logrus.DebugLevel
	logger.Formatter = &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: logTimeStampFormat,
	}
	return logger
}

// NewHook builds a logrus.Hook that writes output to rotated log files
func NewHook(logDir, baseName, extension string, maxFileSize int64, now clock) logrus.Hook {
	// Log file format to write stuff to disk. Messages will look like the following:
	// time="2017/01/23 08:51:59.483839" level=info msg=testing caller="filelogger_test.go:35"
	formatter := &logrus.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: logTimeStampFormat,
	}
	hook := &fileSystemHook{
		logDir:       logDir,
		baseName:     baseName,
		extension:    extension,
		formatter:    formatter,
		stderrLogger: newStderrLogger(),
		maxFileSize:  maxFileSize,
		now:          now,
	}

	if err := os.MkdirAll(hook.logDir, 0776); err != nil { // nolint: gas
		hook.stderrLogger.Fatal("Error setting up logger: ", err)
	}

	// Set up initial log file
	hook.rotate()

	return hook
}

// This logger handles all levels of logging if needbe
func (h *fileSystemHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Opens up a new log file that hasn't existed before. Since milliseconds are part of the log file format, we wait
// for the roll over of the millisecond between retries. This method will block during a log statement.
// If we are unable to find a new file after 10 tries, bail. This should only really happen if we are colliding
// with another instance of the logger
func (h *fileSystemHook) openNewLogFile() (*os.File, error) {
	var filename string
	var logFilePath string
	for tries := 0; tries < 10; tries++ {
		now := h.now()
		formattedTime := now.Format(logFileNameFormat)
		formattedTime = strings.Replace(formattedTime, ".", "_", -1)

		filename = fmt.Sprintf("%s_%s.%s", h.baseName, formattedTime, h.extension)
		logFilePath = filepath.Join(h.logDir, filename)

		if f, err := os.OpenFile(logFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_EXCL, 0666); err == nil { // nolint: gas
			return f, nil
		} else if err.(*os.PathError).Err != syscall.EEXIST {
			return nil, err
		}
		// Sleep for one millisecond -- the time should roll over
		time.Sleep(1 * time.Millisecond)
		h.stderrLogger.Warning("Duplicate filename: ", tries, ": ", logFilePath)
	}
	return nil, errors.New(fmt.Sprint("Could not open file: ", filename))
}

// Changes the active log file link, which is just baseName.extension. -> activeLogFile
// This doesn't return an error, because if we're unable to relink this, it's not fatal, and we shouldn't bail
// Unfortunately, this information is not logged to the log file itself, but stderr because it creates a cycle
// if we end up triggering the default Logrus instance
func (h *fileSystemHook) relink() {
	linkTmpName := fmt.Sprintf("%s.%s.tmp", h.baseName, h.extension)
	linkTmpPath := filepath.Join(h.logDir, linkTmpName)

	linkName := fmt.Sprintf("%s.%s", h.baseName, h.extension)
	linkPath := filepath.Join(h.logDir, linkName)
	err := os.Remove(linkTmpPath)
	if !(err == nil || err.(*os.PathError).Err == syscall.ENOENT) {
		h.stderrLogger.Error("Unable to remove temp link for current log file: ", err)
		return
	}

	if err := os.Symlink(filepath.Base(h.currentFile.Name()), linkTmpPath); err != nil {
		h.stderrLogger.Error("Could not link current log file: ", err)
	}
	if err := os.Rename(linkTmpPath, linkPath); err != nil {
		h.stderrLogger.Error("Could not rename temp link to current log file: ", err)
	}
}

func (h *fileSystemHook) rotate() {
	if h.currentFile != nil {
		oldName := h.currentFile.Name()
		err := h.currentFile.Close()
		if err != nil {
			h.stderrLogger.Warningf("Unable to close current logfile '%s', because: '%v' -- may be leaking file descriptors", oldName, err)
		}
	}

	if f, err := h.openNewLogFile(); err != nil {
		h.stderrLogger.Fatal("Could not open log file: ", err)
	} else {
		h.currentFile = f
	}
	h.relink()
	h.currentSize = 0
}

// This method handles serializing
func (h *fileSystemHook) Fire(entry *logrus.Entry) error {
	h.Lock()
	defer h.Unlock()
	if h.currentSize >= h.maxFileSize {
		h.rotate()
	}
	if h.currentFile == nil {
		h.stderrLogger.Fatal("Write invoked with no current file")
	}

	line, err := h.formatter.Format(entry)
	delete(entry.Data, "caller")
	if err != nil {
		return err
	}

	// TODO(sdhillon): determine if we need to check that writtenBytes == len(line), to avoid truncated long lines
	writtenBytes, err := h.currentFile.Write(line)
	if err != nil {
		return err
	}
	h.currentSize = h.currentSize + int64(writtenBytes)

	return nil
}
