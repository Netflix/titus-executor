package filesystems

import (
	"context"
	"io/ioutil"
	"math/rand"
	_ "net/http/pprof" //nolint:gosec
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/filesystems/xattr"
	"github.com/Netflix/titus-executor/uploader"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func makeWatcher(localDir, uploadDir string) *Watcher {
	config := WatchConfig{
		localDir:              localDir,
		uploadDir:             uploadDir,
		uploadRegexp:          nil,
		uploadCheckInterval:   time.Second * 2,
		uploadThresholdTime:   time.Second * 10,
		stdioLogCheckInterval: time.Second * 2,
		keepFileAfterUpload:   false,
	}

	uploader := uploader.NewUploaderWithBackend(uploader.NewCopyBackend("."))

	return &Watcher{
		config:   config,
		uploader: uploader,
	}
}

func TestWatcher(t *testing.T) {
	t.Parallel()
	tmp, err := ioutil.TempDir(".", "task-logs-")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll(tmp) // nolint: vetshadow
		if err != nil {
			t.Fatal(err)
		}
	}()

	helloBytes := []byte("hello\nprana\n")
	prana1 := filepath.Join(tmp, "/prana-log-20161001-19.log")
	err = ioutil.WriteFile(prana1, helloBytes, 0644) // nolint: gosec
	if err != nil {
		t.Fatal(err)
	}
	require.NoError(t, xattr.SetXattr(prana1, xattr.MimeTypeAttr, []byte("application/binary")))

	time.Sleep(time.Second * 10)

	prana2 := filepath.Join(tmp, "/prana-log-20161001-20.log")
	err = ioutil.WriteFile(prana2, helloBytes, 0644) // nolint: gosec
	if err != nil {
		t.Fatal(err)
	}
	require.NoError(t, xattr.SetXattr(prana2, xattr.MimeTypeAttr, []byte("application/binary")))

	destLoc, err := ioutil.TempDir(".", "s3-logs-")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll(destLoc) // nolint: vetshadow
		if err != nil {
			t.Fatal(err)
		}
	}()
	w := makeWatcher(tmp, destLoc)
	err = w.Watch(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second * 5)

	verifyTestWatcher(destLoc, t)

	assert.NoError(t, w.Stop())
	if err != nil {
		t.Fatal("Could not stop watcher: ", err)
	}
	assert.NoError(t, w.Stop(), "Stopping the watcher a second time did something odd")
}

func verifyTestWatcher(destLoc string, t *testing.T) {
	fileInfos, err := ioutil.ReadDir(destLoc) // nolint: ineffassign
	if err != nil {
		t.Fatal(err)
	}
	if len(fileInfos) != 1 {
		t.Fatalf("Expected number of files did not get uploaded (1 vs %d)", len(fileInfos))
	}
	assert.Equal(t, "application/binary", xattr.GetMimeType(filepath.Join(destLoc, fileInfos[0].Name())))
}

func TestDoubleUpload(t *testing.T) { // nolint: gocyclo
	t.Parallel()
	const logFileName = "samefile1.log"
	tmp, err := ioutil.TempDir(".", "task-logs-")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll(tmp) // nolint: vetshadow
		if err != nil {
			t.Fatal(err)
		}
	}()

	destLoc, err := ioutil.TempDir(".", "s3-logs-")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll(destLoc) // nolint: vetshadow
		if err != nil {
			t.Fatal(err)
		}
	}()

	w := makeWatcher(tmp, destLoc)
	err = w.Watch(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	helloBytes1 := []byte("hello\nprana1\n")
	err = ioutil.WriteFile(filepath.Join(tmp, logFileName), helloBytes1, 0644) // nolint: gosec
	if err != nil {
		t.Fatal(err)
	}

	// Please don't smite me.
	for i := 0; i < 20; i++ {
		time.Sleep(1 * time.Second)
	}
	wd, _ := os.Getwd()
	t.Log("WD: ", wd)
	data, err := ioutil.ReadFile(filepath.Join(destLoc, logFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, helloBytes1) {
		t.Fatal("Content, not reloaded, instead it is: ", string(data))
	}

	helloBytes2 := []byte("hello\nprana2\n")
	err = ioutil.WriteFile(filepath.Join(tmp, logFileName), helloBytes2, 0644) // nolint: gosec
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Second)

	data, err = ioutil.ReadFile(filepath.Join(destLoc, logFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, helloBytes2) {
		t.Fatal("Content, not helloBytes2, instead it is: ", string(data))
	}

	helloBytes3 := []byte("hello\nprana3\n")
	err = ioutil.WriteFile(filepath.Join(tmp, logFileName), helloBytes3, 0644) // nolint: gosec
	if err != nil {
		t.Fatal(err)
	}

	err = w.Stop()
	if err != nil {
		t.Fatal(err)
	}

	data, err = ioutil.ReadFile(filepath.Join(destLoc, logFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, helloBytes3) {
		t.Fatal("Content, not helloBytes3, instead it is: ", string(data))
	}
}

func TestRotateRegexp(t *testing.T) {
	allLogsRegexp := regexp.MustCompile(`^[\w \d \. _ -]*log$`)

	var testData = []struct {
		filename string
		result   bool
		regexp   *regexp.Regexp
	}{
		{"stdout", false, nil},
		{"stdout.2", true, nil},
		{"stout.2", false, nil},
		{"stdout.30092016_151555.073", true, nil},
		{"stderr.70092016_151555.07888", true, nil},
		{"stderr.foobar.4555.", false, nil},
		{"stderr.70092016_151555.07888.backup", false, nil},
		{"tomcat-startup.log", false, nil},
		{"nodequark.core.13213.3213", true, nil},
		{"nodequark.core.13213.abb.3213", false, nil},
		{"propsapi_i-4a7ec3d1_tomcat_catalina.out_20160329_1352.log", true, allLogsRegexp},
		{"stderr.20", true, allLogsRegexp},
		{"propsapi_i-0827338c_tomcat_catalina.out_20160414_0124.log", true, allLogsRegexp},
		{"catalina_20200330_21.out", true, nil},
	}

	for _, td := range testData {
		shouldRotate := CheckRegexpMatch(td.filename, td.regexp)
		if td.result {
			assert.True(t, shouldRotate, "%s should rotate", td.filename)
		} else {
			assert.False(t, shouldRotate, "%s should not rotate", td.filename)
		}
	}
}

// The logfile to use during the testing of log rotate code
const logFileName = "stderr"

func TestLogRotate(t *testing.T) {
	if os.Getenv("CIRCLECI") == "true" {
		t.Skip("See: https://discuss.circleci.com/t/xattrs-broken-on-docker/30152")
	}
	t.Parallel()
	rotateSize = 5000011 // 5MB-ish -- this is a prime number intentionally
	maxSeek = 1000003
	tmpLogDir, err := ioutil.TempDir(".", "src-logs-")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll(tmpLogDir) // nolint: vetshadow
		if err != nil {
			t.Fatal(err)
		}
	}()

	destLogDir, err := ioutil.TempDir(".", "dst-logs-")
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := os.RemoveAll(destLogDir) // nolint: vetshadow
		if err != nil {
			t.Fatal(err)
		}
	}()
	testLogRotateMain(tmpLogDir, destLogDir, t)
}

func setupLogRotate(tmpLogDir, destLogDir string, t *testing.T) (*Watcher, []byte) {
	file, err := os.OpenFile(filepath.Join(tmpLogDir, logFileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0777)
	if err != nil {
		t.Fatal("Couldn't open log file: ", err)
	}
	err = xattr.FSetXattr(file, StdioAttr, []byte{})
	if err != nil {
		t.Fatal("Could not set xattr on file: ", err)
	}
	defer mustClose(file)

	w := makeWatcher(tmpLogDir, destLogDir)

	err = w.Watch(context.TODO())
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(3 * time.Second)

	buf := []byte{}
	// Write a little bit more than the watcher intends
	for x := 0; x < 4; x++ {
		l1 := len(buf)
		logrus.Debugf("Begin write at %d bytes", l1)
		tmpBuf := []byte{}
		// We do * 2 here, because we want to ensure there's enough space for a \n and to trigger rotation
		for int64(len(tmpBuf)) < rotateSize*2 {
			idx := rand.Intn(len(loremIpsum)) // nolint: gosec
			tmpBuf = append(tmpBuf, loremIpsum[idx]...)
		}
		_, err = file.Write(tmpBuf)
		if err != nil {
			t.Fatal("Could not write log file data: ", err)
		}
		buf = append(buf, tmpBuf...)
		l2 := len(buf)
		logrus.Debugf("Wrote %d bytes", l2-l1)
		time.Sleep(3 * time.Second)
	}

	// This should make sure that there have been at least 10 seconds since the first elapsed loop
	time.Sleep(3 * time.Second)

	return w, buf
}

func checkOngoingLogRotate(tmpLogDir, destLoc string, buf []byte, t *testing.T) { // nolint: gocyclo
	files, err := ioutil.ReadDir(destLoc)
	if err != nil {
		t.Fatal("Unable to list destloc files")
	}

	filepaths := map[string]string{}

	movedFiles := []string{}
	for _, f := range files {
		// Really not sure why we need to do this?
		if f.Size() < int64(rotateSize) { // nolint:unconvert
			t.Fatalf("Rotated incorrect amount in file %s, file size: %d, expect size at least: %d", f.Name(), f.Size(), rotateSize)
		}
		movedFiles = append(movedFiles, f.Name())
		filepaths[f.Name()] = filepath.Join(destLoc, f.Name())
	}

	sort.Strings(movedFiles)

	rotatedBuf := []byte{}
	for _, f := range movedFiles {
		data, err := ioutil.ReadFile(filepaths[f])
		if err != nil {
			t.Fatal("Unable to read data from file: ", f)
		}
		if data[len(data)-1] != '\n' {
			t.Fatalf("File '%s' didn't end in newline", f)
		}
		rotatedBuf = append(rotatedBuf, data...)
	}
	compareBuffers(rotatedBuf, buf, t)
}

func compareBuffers(rotatedBuf, buf []byte, t *testing.T) {
	t.Log("len(rotatedBuf) = ", len(rotatedBuf))
	t.Log("len(buf) = ", len(buf))
	if !reflect.DeepEqual(rotatedBuf, buf[:len(rotatedBuf)]) {
		for i := 0; i < len(rotatedBuf); i++ {
			if rotatedBuf[i] != buf[i] {
				t.Log("Original Buf: ", string(buf[max(i-10, 0):min(i+10, len(buf))]))
				t.Log("Rotated Buf: ", string(rotatedBuf[max(i-10, 0):min(i+10, len(rotatedBuf))]))
				t.Fatal("Data lost during rotation, location: ", i)

			}
		}
	}
}

func testLogRotateMain(tmpLogDir, destLogDir string, t *testing.T) {
	w, buf := setupLogRotate(tmpLogDir, destLogDir, t)
	checkOngoingLogRotate(tmpLogDir, destLogDir, buf, t)

	err := w.Stop()
	if err != nil {
		t.Fatal("Could not stop watcher: ", err)
	}
	checkPostLogRotate(destLogDir, buf, t)

}

func checkPostLogRotate(destLogDir string, buf []byte, t *testing.T) { // nolint: gocyclo
	dstLogFiles := []string{}

	destLogs, err := ioutil.ReadDir(destLogDir)
	if err != nil {
		t.Fatal("Unable to read destination log files: ", err)
	}
	for _, f := range destLogs {
		if path.Base(f.Name()) != logFileName {
			dstLogFiles = append(dstLogFiles, f.Name())
		}
		t.Logf("Destination Log File: %+v", f)
	}
	sort.Strings(dstLogFiles)
	// Always put the final log file at the end
	dstLogFiles = append(dstLogFiles, logFileName)

	if len(dstLogFiles) > 6 || len(dstLogFiles) < 4 {
		t.Fatal("Unexpected number of log files: ", len(dstLogFiles))
	}

	allFilebuf := []byte{}
	t.Log("Concatenating files in: ", strings.Join(dstLogFiles, " -> "))
	for _, fn := range dstLogFiles {
		var data []byte
		data, err = ioutil.ReadFile(filepath.Join(destLogDir, fn))
		if err != nil {
			t.Fatalf("Cannot read log file %s because error: %+v ", fn, err)
		}
		allFilebuf = append(allFilebuf, data...)
	}

	compareBufPostLogRotate(buf, allFilebuf, t)
}

func compareBufPostLogRotate(buf, allFilebuf []byte, t *testing.T) {
	t.Log("len(allFileBuf) = ", len(allFilebuf))
	t.Log("len(buf) = ", len(buf))
	if !reflect.DeepEqual(allFilebuf, buf) {
		for i := 0; i < min(len(allFilebuf), len(buf)); i++ {
			if allFilebuf[i] != buf[i] {
				t.Log("Original Buf: ", string(buf[max(i-10, 0):min(i+10, len(buf))]))
				t.Log("allFilebuf Buf: ", string(allFilebuf[max(i-10, 0):min(i+10, len(allFilebuf))]))
				t.Fatal("Data lost, location: ", i)

			}
		}
	}
}
