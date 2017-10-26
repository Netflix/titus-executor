package filelogger

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	time1 = time.Unix(0, 0).In(getTz("PST8PDT"))
	time2 = time.Unix(1, 0).In(getTz("PST8PDT"))
)

func getTz(name string) *time.Location {
	if tz, err := time.LoadLocation(name); err != nil {
		panic(err)
	} else {
		return tz
	}
}
func TestLogger(t *testing.T) {
	logDir, err := ioutil.TempDir(".", "logs-test")
	if err != nil {
		t.Fatal("Failed to create tmp dir: ", err)
	}
	t.Log("Using log dir: ", logDir)

	chanTime := make(chan time.Time)

	go func() {
		defer close(chanTime)
		chanTime <- time1
		chanTime <- time1
		// Make sure that
		chanTime <- time2

	}()
	clock := func() time.Time {
		return <-chanTime
	}
	logrus.AddHook(NewHook(logDir, "test", "log", 10, clock))

	logrus.SetLevel(logrus.InfoLevel)

	// Make sure this isn't logged
	logrus.Debug("testing-debug")

	for i := 0; i < 2; i++ {
		logrus.Infoln("testing")
	}

	verifyFileCounts(logDir, t, 1, 2)

	_, ok := <-chanTime
	if ok {
		t.Fatal("Not exactly three values read off time channel")
	}

	// Verify the exact files:
	logFileName1 := "test_1969_12_31_16_00_00_000.log"
	logFileName2 := "test_1969_12_31_16_00_01_000.log"

	exists(t, logDir, logFileName1)
	exists(t, logDir, logFileName2)

	// Make sure that the current log file link is correct
	if path, err := os.Readlink(filepath.Join(logDir, "test.log")); err != nil {
		t.Fatal("Unable to read test.log link: ", err)
	} else if path != logFileName2 {
		t.Fatal("Current test.log not linked to current file, instead: ", path)
	}

	// We don't remove the log directory if the test failed
	if err := os.RemoveAll(logDir); err != nil {
		t.Logf("Failed to remove %s because %v", logDir, err)
	}
}

func verifyFileCounts(logDir string, t *testing.T, expectedSymLinkCount, expectedEegularFileCount int) {
	symlinks := 0
	regularFiles := 0

	files, err := ioutil.ReadDir(logDir)
	if err != nil {
		t.Errorf("Error reading %v - %v", logDir, err)
	}
	for _, fileInfo := range files {
		switch fileInfo.Mode() & os.ModeType {
		case 0:
			regularFiles++
		case os.ModeSymlink:
			symlinks++
		default:
			t.Fatal("Unexpected file type: ", fileInfo)
		}
	}
	t.Log("Total regular files created: ", regularFiles)
	t.Log("Total symlinks created:", symlinks)

	if regularFiles != expectedEegularFileCount {
		t.Fatal("Unexpected number of regular files: ", regularFiles)
	}
	if symlinks != expectedSymLinkCount {
		t.Fatal("Unexpected number of symlinks")

	}
}
func exists(t *testing.T, logDir, filename string) {
	if _, err := os.Stat(filepath.Join(logDir, filename)); err != nil {
		t.Fatalf("Unable to get info on file '%s' because: %v", filename, err)
	}
}
