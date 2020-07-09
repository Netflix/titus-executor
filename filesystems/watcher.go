package filesystems

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Netflix/titus-executor/uploader"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/filesystems/xattr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
)

const (
	backupFileTimeFormat = "02012006_150405.999"
	// VirtualFilePrefix is the attribute namespace used to state virtual file mappings
	VirtualFilePrefix = "user.titus.virtualFile"
	// VirtualFilePrefixWithSeparator is the VirtualFilePrefix with a "." appended (the namespace separator
	VirtualFilePrefixWithSeparator = VirtualFilePrefix + "."
	// StdioAttr is the attribute that states this is a stdio, rotatable file
	StdioAttr                    = "user.stdio"
	waitForDieAfterContextCancel = time.Minute
)

var (
	// This is a variable so we can change it as necessary during tests
	rotateSize int64 = 256000000
	maxSeek    int64 = 16777216 // 16MB

)

type stdioRotateMode int

const (
	normalRotate stdioRotateMode = iota
	finalUpload
)

// PotentialStdioNames are the relative paths to the base logging directory that could have stdio in them. Pretend this is an ImmutableSet
var PotentialStdioNames = map[string]struct{}{
	"stderr": {},
	"stdout": {},
}

// We rely on potentialStdioNames not matching any of the regexes here. Otherwise "bad" things will happen.
var defaultUploadRegexpList = []*regexp.Regexp{
	regexp.MustCompile(`\.complete$`),
	regexp.MustCompile(`stdout.[\d_\.]+$`),
	regexp.MustCompile(`stderr.[\d_\.]+$`),
	regexp.MustCompile(`[\d-_]+.log`),
	regexp.MustCompile(`[\d-_]+.out`),
	regexp.MustCompile(`[\S]+\.core\.[\d]+\.[\d]+`),
}

type WatchConfig struct {
	localDir              string
	uploadDir             string
	uploadRegexp          *regexp.Regexp
	uploadCheckInterval   time.Duration // The interval at which we check for files that need uploading.
	uploadThresholdTime   time.Duration // Duration for which a file must be untouched to be uploader.
	stdioLogCheckInterval time.Duration
	keepFileAfterUpload   bool
}

func NewWatchConfig(localDir, uploadDir string, uploadRegexp *regexp.Regexp, uploadCheckInterval, uploadThresholdTime, stdioLogCheckInterval time.Duration, keepFileAfterUpload bool) WatchConfig {
	return WatchConfig{
		localDir:              localDir,
		uploadDir:             uploadDir,
		uploadRegexp:          uploadRegexp,
		uploadCheckInterval:   uploadCheckInterval,
		uploadThresholdTime:   uploadThresholdTime,
		stdioLogCheckInterval: stdioLogCheckInterval,
		keepFileAfterUpload:   keepFileAfterUpload,
	}
}

type Watcher struct {
	metrics  metrics.Reporter
	config   WatchConfig
	uploader *uploader.Uploader

	retError     error
	dieCh        chan struct{}
	doneCh       chan struct{}
	started      int32
	shutdownOnce sync.Once
}

// NewWatcher returns a fully instantiated instance of Watcher, which will run until Stop is called.
func NewWatcher(m metrics.Reporter, c WatchConfig, u *uploader.Uploader) (*Watcher, error) {
	watcher := &Watcher{
		metrics:  m,
		config:   c,
		uploader: u,
	}

	return watcher, nil
}

func (w *Watcher) shouldRotate(file string) bool {
	return CheckFileForRotation(file, w.config.uploadRegexp)
}

/*
The rules of externally rotated files:
- They must only be opened by writers O_APPEND
- They should write line breaks (often), and be text, and line-oriented
- They must never be deleted
- They must only be read by an ERF aware reader, or a reader which ignores NULLs
	This is actually kind of interesting -- although reading from holes doesn't really produce I/O,
	you end up paying the syscall cost + memcpy cost. That raw cost is in the single-digit microseconds.
	It might actually be more efficient for ERF readers to just seek to the first non-null byte in a file
	by reading it, and then skipping to a newline.

	This sounds good, but it also sounds complicated, and I'll prefer laziness over complexity.

	There is also a TODO to enforce this logic by setting attributes on the file like. More on this later.
	a - append
	i - immutable

When we rotate them, we create an attribute:
user.titus.virtualFile.${TIMESTAMP} which is equal a string formatted like so: "start,length",
The current active start is the value of user.stdio. If user.stdio is a 0-lengthed value, then it means this is starting from the physical start of the file

You can derive virtual filename by taking the basename and formatting it with fileName + "." + ${TIMESTAMP}

where the virtual filename ${NAME} would actually be at the offsets [start, start+length)

When we upload these, if the delete flag is set to true, then we blow away that chunk of file bits.

This _can_ run into the condition where we don't have enough quota to create the attribute, but I have patches out to the btrfs list for users with cap_sys_resource
to be able to blow the quota temporarily.

If we're so close to the quota where we don't have say ~65 bytes available (assuming ~24 characters for ${NAME}) in quota during the rotation,
it'll make me sad. We could do tricks to stash free space in other places, but unfortunately, due to racing, we could still get stuck.

One "interesting" avenue I have yet to explore is how items get packed. It seems to vary, but it seems like there is some universality of eager allocation
and then pessimistic expansion.
*/

// CheckFileForStdio determines whether the file at the path below is one written by tini as a stdio rotator
func CheckFileForStdio(fileName string) bool {
	_, err := xattr.GetXattr(fileName, StdioAttr)
	if err == xattr.ENOATTR {
		return false
	} else if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Errorf("error reading attr %s from file %s: %v", StdioAttr, fileName, err)
	}

	return true
}

func CheckFileForRotation(fileName string, regexp *regexp.Regexp) bool { // nolint: golint
	fileNameBytes := []byte(fileName)
	rotateIt := regexp != nil && regexp.Match(fileNameBytes)
	if rotateIt {
		return true
	}

	for _, rg := range defaultUploadRegexpList {
		rotateIt = rg.Match(fileNameBytes)
		if rotateIt {
			return true
		}
	}
	return false
}

// Watch kicks off the watch loop of the Watcher
func (w *Watcher) Watch(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&w.started, 0, 1) {
		panic("Watcher started twice")
	}

	log.WithField("localDir", w.config.localDir).WithField("uploadDir", w.config.uploadDir).WithField("uploadCheckInterval", w.config.uploadCheckInterval).Info("starting watchLoop")

	// We initialize there here because otherwise we would have to teach watcher_test about these
	w.dieCh = make(chan struct{})
	w.doneCh = make(chan struct{})

	go w.watchLoop(ctx)
	return nil
}

func (w *Watcher) watchLoop(parentCtx context.Context) {
	// Let folks know we're done here. This way we don't have to explicitly kill it
	defer close(w.doneCh)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Wait group to wait for the inner watchers to shut down
	wg := &sync.WaitGroup{}
	go w.stdioRotateLoop(ctx, wg)
	go w.traditionalRotateLoop(ctx, wg)

	// Wait for one of the die mechanisms to kick in
	select {
	case <-ctx.Done():
		// If this happens, let's wait to see if dieCh stops in some timeout
		select {
		case <-w.dieCh:
		case <-time.After(waitForDieAfterContextCancel):
		}
	case <-w.dieCh:
	}

	// No matter what cancel our context, so our children shut down
	cancel()

	log.Debug("Watcher shutting down")

	finalCtx, finalCancel := context.WithTimeout(parentCtx, 5*time.Minute)
	defer finalCancel()
	// Wait for both loops to wrap up. This runs in theoretically unbounded time.
	// At least we will throw an error if it takes more than 2 minutes to shut down
	t := time.AfterFunc(120*time.Second, func() {
		// TODO: We should do something to preempt the wait below
		log.Error("Watchloop took too long to shutdown")
	})
	wg.Wait()
	t.Stop()

	w.stdioRotate(finalCtx, finalUpload)
	if err := finalCtx.Err(); err != nil {
		w.retError = err
		return
	}
	// Set retError
	w.retError = w.uploadAllLogFiles(finalCtx)

	// Cleanup is done by all of the above defers!
}

// Although we could parameterize these loops, I want to keep them separate in case we need to debug from a goroutine dump
func (w *Watcher) stdioRotateLoop(parentCtx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Our Ticker automatically stops
	c := newTicker(ctx, w.config.stdioLogCheckInterval)

	for range c {
		w.stdioRotate(ctx, normalRotate)
	}
}

func (w *Watcher) traditionalRotateLoop(parentCtx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Our Ticker automatically stops
	c := newTicker(ctx, w.config.uploadCheckInterval)
	log.Debug("Rotate interval: ", w.config.uploadCheckInterval.String())

	for range c {
		w.traditionalRotate(ctx)
	}
}

// Traditional rotate doesn't actually rotate at all
// it goes through a list of files, and checks when they were modified, and based upon that it uploads them and optionally deletes them
func (w *Watcher) traditionalRotate(ctx context.Context) {
	logFileList, err := buildFileListInDir(w.config.localDir, true, w.config.uploadThresholdTime)
	if err == nil {
		for _, logFile := range logFileList {
			w.uploadLogfile(ctx, logFile)
		}
	} else {
		log.Error(err)
	}
}

func (w *Watcher) stdioRotate(ctx context.Context, mode stdioRotateMode) {
	for potentialStdioName := range PotentialStdioNames {

		fullPath := filepath.Join(w.config.localDir, potentialStdioName)
		log.WithField("filename", fullPath).WithField("mode", mode).Debug("Stdio checking for rotation")

		if !CheckFileForStdio(fullPath) {
			continue
		}
		log.WithField("filename", fullPath).WithField("mode", mode).Debug("Stdio rotating")
		file, err := os.OpenFile(fullPath, os.O_RDWR, 0)
		if err != nil {
			log.Errorf("Could not open %s because: %v", fullPath, err)
			continue
		}

		defer shouldClose(file)
		// 1. Check for old virtual files that can be reclaimed:
		// if so upload 'em, punch a hole in 'em, and discard 'em
		w.doStdioUploadAndReclaim(ctx, mode, file)

		if mode == normalRotate {
			w.doStdioRotate(file)
		} else if mode == finalUpload {
			w.doFinalStdioUploadAndReclaim(ctx, file)
		}

	}
}

func (w *Watcher) doFinalStdioUploadAndReclaim(ctx context.Context, file *os.File) {
	w.doStdioUploadAndReclaim(ctx, finalUpload, file)

	cutLoc, err := GetCurrentOffset(file)
	if err != nil {
		log.Errorf("Could not upload stdio file %s because: %v", file.Name(), err)
		return
	}
	log.WithField("cutLoc", cutLoc).WithField("filename", file.Name()).Debug("Uploading stdio file")

	fullRemoteFilePath := path.Join(w.config.uploadDir, path.Base(file.Name()))

	if err := w.uploader.UploadPartOfFile(ctx, file, cutLoc, math.MaxInt64, fullRemoteFilePath, ""); err != nil {
		w.metrics.Counter("titus.executor.logsUploadError", 1, nil)
		log.Errorf("watch: error uploading %s: %s", file.Name(), err)
	}
}

func (w *Watcher) doStdioUploadAndReclaim(ctx context.Context, mode stdioRotateMode, file *os.File) {
	xattrList, err := xattr.FListXattrs(file)
	if err != nil {
		log.Warningf("Could not fetch xattr list for %s, because %v, not uploading and reclaiming", file.Name(), err)
		return
	}

	keys := make([]string, len(xattrList))
	i := 0
	for key := range xattrList {
		keys[i] = key
		i++
	}
	sort.Strings(keys)

	// The set needs to be sorted before we stick it in, otherwise if there are two files up for collection, say A and B, and B is earlier in the map
	// it could end up making the hole from 0 (bytes) -> end of B, and drop A's bytes in the process.
	// We make the holes from 0 because the holes have to be block aligned

	// It seems the sort order (or iteration order) of Go's maps is unstable as well, so this is difficult to test for.
	for _, xattrKey := range keys {
		if !strings.HasPrefix(xattrKey, VirtualFilePrefixWithSeparator) {
			continue
		}
		start, len, err := FetchStartAndLen(xattrKey, file)
		if err == nil {
			w.doStdioUploadAndReclaimVirtualFile(ctx, mode, start, len, xattrKey, file)
		}
	}
}

// FetchStartAndLen returns the virtual file start and length for a given xattrKey (a key that includes the prefix)
func FetchStartAndLen(xattrKey string, file *os.File) (int64, int64, error) {
	xattrValBytes, err := xattr.FGetXattr(file, xattrKey)
	if err != nil {
		log.Errorf("Could not get attribute value for key %s because: %v", xattrKey, err)
		return 0, 0, err
	}

	xattrValSplitStr := strings.Split(string(xattrValBytes), ",")
	if len(xattrValSplitStr) != 2 {
		log.Errorf("Attribute %s value '%s' invalid because split size not 2", xattrKey, string(xattrValBytes))
		return 0, 0, err
	}

	start, err := strconv.ParseInt(xattrValSplitStr[0], 10, 64)
	if err != nil {
		log.Errorf("Attribute %s value '%s' start invalid because %v", xattrKey, string(xattrValBytes), err)
		return 0, 0, err
	}

	length, err := strconv.ParseInt(xattrValSplitStr[1], 10, 64)
	if err != nil {
		log.Errorf("Attribute %s value '%s' len invalid because %v", xattrKey, string(xattrValBytes), err)
		return 0, 0, err
	}

	return start, length, nil
}

func (w *Watcher) doStdioUploadAndReclaimVirtualFile(ctx context.Context, mode stdioRotateMode, start, length int64, xattrKey string, file *os.File) {

	log.WithField("start", start).WithField("length", length).WithField("xattrKey", xattrKey).WithField("filename", file.Name()).Debug("Stdio upload and reclaim")
	virtualFileSuffix := strings.TrimPrefix(xattrKey, VirtualFilePrefixWithSeparator)
	virtualFileName := strings.Join([]string{path.Base(file.Name()), virtualFileSuffix}, ".")

	creationTime, err := time.Parse(backupFileTimeFormat, virtualFileSuffix)
	if err != nil {
		log.Errorf("Could not parse virtual file suffix '%s' because: %v", virtualFileSuffix, err)
		return
	}

	now := time.Now()
	age := now.Sub(creationTime)
	if mode == normalRotate && age > w.config.uploadThresholdTime {
		log.Debugf("Virtual file %s of real file %s not old enough to upload and discard because only %s old", virtualFileName, file.Name(), age.String())
		return
	}

	log.Debugf("Uploading virtual file %s of real file %s because it is %s old", virtualFileName, file.Name(), age.String())
	// This relies on the fact that the stdio files are always in the root directory
	fullRemoteFilePath := path.Join(w.config.uploadDir, virtualFileName)

	if err := w.uploader.UploadPartOfFile(ctx, file, start, length, fullRemoteFilePath, ""); err != nil {
		w.metrics.Counter("titus.executor.logsUploadError", 1, nil)
		log.Errorf("watch: error uploading %s's %s: %s", file.Name(), virtualFileName, err)
	}

	if !w.config.keepFileAfterUpload {
		holeSize := start + length - 1
		log.WithField("filename", file.Name()).WithField("xattrKey", xattrKey).WithField("holeSize", holeSize).Debug("Deleting old file")
		err = xattr.FDelXattr(file, xattrKey)
		if err != nil {
			log.Errorf("Could not delete attr %s on file %s, not punching hole because: %v", xattrKey, file.Name(), err)
		}

		err = xattr.MakeHole(file, 0, holeSize)
		if err != nil {
			log.Errorf("Could not make hole in file %s, because: %v", file.Name(), err)
		}
	}

}

func (w *Watcher) doStdioRotate(file *os.File) {
	// 2. Get the current active offset from stdioAttr
	currentOffset, err := GetCurrentOffset(file)
	if err != nil {
		return
	}

	// 3. See if the file has gone exceeded the size beyond the active offset to justify rotating
	currentSize, err := getSize(file)
	if err != nil {
		return
	}
	log.WithField("fileName", file.Name()).WithField("currentSize", currentSize).WithField("currentOffset", currentOffset).Debug("doing stdio rotate")

	if currentSize-currentOffset < rotateSize {
		log.Debugf("Not rotating %s, because current size only %d bytes, and current offset %d, total delta: %d", file.Name(), currentSize, currentOffset, currentSize-currentOffset)
		return
	}

	// 4. Find an appropriate place to cut
	cutLoc, err := getCutOffset(file)
	if err != nil {
		log.Errorf("Could not get file for '%s' because: %v", file.Name(), err)
	}

	// 5. Update stdioattr, and write a new virtual file record
	err = updateFile(currentOffset, cutLoc, file)
	if err != nil {
		log.Errorf("Unable to setup virtual file attrs for '%s' because %v", file.Name(), err)
		return
	}
}

// updateFile creates a new xattr and sets the current stdioattr to start at cutLoc
func updateFile(currentOffset, cutLoc int64, file *os.File) error {
	now := time.Now()
	nowStr := now.UTC().Format(backupFileTimeFormat)
	log.WithField("now", now).WithField("currentOffset", currentOffset).WithField("cutLoc", cutLoc).WithField("filename", file.Name()).Debug("updating file")

	// Using strings here to make it more clear to show what's going on
	newAttrKey := strings.Join([]string{VirtualFilePrefix, nowStr}, ".")
	curOffsetStr := strconv.FormatInt(currentOffset, 10)
	virtualFileLengthStr := strconv.FormatInt(cutLoc-currentOffset, 10)
	newAttrVal := strings.Join([]string{curOffsetStr, virtualFileLengthStr}, ",")

	err := xattr.FSetXattr(file, newAttrKey, []byte(newAttrVal))
	if err != nil {
		return err
	}

	err = xattr.FSetXattr(file, StdioAttr, []byte(strconv.FormatInt(cutLoc, 10)))
	if err != nil {
		tmpErr := xattr.FDelXattr(file, newAttrKey)
		if tmpErr != nil {
			log.Errorf("Could not roll back adding virtual file %s because: %v", newAttrKey, tmpErr)
		}
		return err
	}

	return nil
}

func getSize(file *os.File) (int64, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		log.Errorf("Could not get size for file for '%s' because: %v", file.Name(), err)
		return 0, err
	}

	return stat.Size, nil
}

// getCutOffset returns the cut offset where a newline exists. If err is not nil, and the returned value is 0, it means no valid cut location was found
func getCutOffset(file *os.File) (int64, error) {
	buf := make([]byte, maxSeek)

	seekOffset, err := file.Seek(-1*maxSeek, io.SeekEnd)
	if err != nil {
		log.Errorf("Could not seek in file %s becuse %v", file.Name(), err)
		return 0, err
	}

	n, err := file.Read(buf)
	if err == io.EOF && n == 0 {
		log.Errorf("Got EOF reading %s from offset %d, and read 0 byes", file.Name(), seekOffset)
		return 0, err
	} else if err != nil {
		log.Errorf("Could not read end buffer in file %s becuse %v", file.Name(), err)
		return 0, err
	}

	newLineIdx := bytes.LastIndexByte(buf, '\n')
	if newLineIdx == -1 {
		log.Errorf("Could not rotate %s because no newline found in last %d bytes", file.Name(), maxSeek)
		return 0, nil
	}

	return seekOffset + int64(newLineIdx) + 1, nil

}

// GetCurrentOffset gets the current place where the "active" file is being written from for a given stdio file
func GetCurrentOffset(file *os.File) (int64, error) {
	currentOffsetBytes, err := xattr.FGetXattr(file, StdioAttr)
	if err != nil {
		log.Errorf("Unable to determine current offset of %s, not doing stdio rotate", file.Name())
		return 0, err
	}

	if len(currentOffsetBytes) != 0 {
		return parsecurrentOffsetBytes(file.Name(), currentOffsetBytes), nil
	}

	return 0, nil
}

func parsecurrentOffsetBytes(name string, currentOffsetBytes []byte) int64 {
	currentOffsetInt, err := strconv.ParseInt(string(currentOffsetBytes), 10, 64)
	if err != nil {
		log.Warningf("Assuming rotation for %s from the start because cannot parse the current offsets '%s' and error: %v", name, string(currentOffsetBytes), err)
		return 0
	}
	return currentOffsetInt
}

// uploadAllLogFiles is called to upload all of the files in the directories
// being watched.
func (w *Watcher) uploadAllLogFiles(ctx context.Context) error {
	logFileList, err := buildFileListInDir(w.config.localDir, false, w.config.uploadThresholdTime)
	if err != nil {
		w.metrics.Counter("titus.executor.logsUploadError", 1, nil)
		log.WithField("localDir", w.config.localDir).Errorf("error uploading %s", err)
		return err
	}

	var errs *multierror.Error

	for _, logFile := range logFileList {
		if ctx.Err() != nil {
			errs = multierror.Append(errs, ctx.Err())
			break
		}
		remoteFilePath, err := filepath.Rel(w.config.localDir, logFile)
		if err != nil {
			log.Printf("Unable to make relative path for %s : %s", logFile, err)
			errs = multierror.Append(errs, err)
			continue
		}
		if CheckFileForStdio(logFile) {
			continue
		}

		err = w.uploader.Upload(ctx, logFile, path.Join(w.config.uploadDir, remoteFilePath), xattr.GetMimeType)
		errs = multierror.Append(errs, err)
	}

	err = errs.ErrorOrNil()
	if err != nil {
		w.metrics.Counter("titus.executor.logsUploadError", len(errs.Errors), nil)
	}

	return err
}

// uploadLogFile is called to upload a single log file while the
// task is running. Currently, no error is returned to the caller,
// it is just logged.
func (w *Watcher) uploadLogfile(ctx context.Context, fileToUpload string) {
	if w.shouldRotate(path.Base(fileToUpload)) {
		// FIXME set content type
		log.Info("Uploading ", fileToUpload)
		remoteFilePath, err := filepath.Rel(w.config.localDir, fileToUpload)
		if err != nil {
			log.Printf("watch : error uploading %s : %s\n", fileToUpload, err)
			return
		}

		if err := w.uploader.Upload(ctx, fileToUpload, path.Join(w.config.uploadDir, remoteFilePath), xattr.GetMimeType); err != nil {
			w.metrics.Counter("titus.executor.logsUploadError", 1, nil)
			log.Printf("watch : error uploading %s : %s\n", fileToUpload, err)
		}
		if !w.config.keepFileAfterUpload {
			if err := os.Remove(fileToUpload); err != nil {
				w.metrics.Counter("titus.executor.logsWatchRemoveError", 1, nil)
				log.Printf("watch : error removing %s : %s\n", fileToUpload, err)
			}
		}
	}
}

func buildFileListInDir(dirName string, checkModifiedTimeThreshold bool, uploadThreshold time.Duration) ([]string, error) {
	return buildFileListInDir2(dirName, []string{}, checkModifiedTimeThreshold, uploadThreshold)
}

func buildFileListInDir2(dirName string, fileList []string, checkModifiedTimeThreshold bool, uploadThreshold time.Duration) ([]string, error) {
	result := fileList
	fileInfos, err := ioutil.ReadDir(dirName)
	if err != nil {
		return result, err
	}

	for _, fileInfo := range fileInfos {
		fqName := path.Join(dirName, fileInfo.Name())

		if fileInfo.IsDir() {
			log.Debugf("descending into %s", fqName)
			return buildFileListInDir2(fqName, result, checkModifiedTimeThreshold, uploadThreshold) // nolint: ineffassign
		}

		if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
			log.Debugf("ignoring %s, %s indicates symlink", fqName, fileInfo.Mode())
			continue
		}

		if checkModifiedTimeThreshold && !isFileModifiedAfterThreshold(fileInfo, uploadThreshold) {
			log.Debugf("ignoring %s, %s not soon enough", fqName, fileInfo.ModTime())
			continue
		}

		if CheckFileForStdio(fqName) {
			log.Debugf("ignoring %s, %s is set", fqName, StdioAttr)
			continue
		}

		log.Printf("adding %s to list of files to upload", fqName)
		result = append(result, fqName)
	}
	return result, nil
}

func isFileModifiedAfterThreshold(file os.FileInfo, uploadThreshold time.Duration) bool {
	return time.Since(file.ModTime()) > uploadThreshold
}

// Stop stops the watcher.
// It can take an indefinite amount of time.
// If it is called before starting, it will panic.
// It can be called multiple times
func (w *Watcher) Stop() error {
	if atomic.LoadInt32(&w.started) != 1 {
		panic("Stopped before started")
	}
	// This should never be called more than once, because it should only be called via the watcher shutdownOnce below
	// This is also why it's an inline function declaraiton
	log.Debug("Watcher asked to shutdown")
	w.shutdownOnce.Do(func() {
		log.Debug("Watcher shutting down")
		close(w.dieCh)
		<-w.doneCh
		log.Debug("Watcher shut down")
	})
	log.Debug("Watcher responded to ask for shutdown")

	return w.retError
}

func shouldClose(file *os.File) {
	name := file.Name()
	if err := file.Close(); err != nil {
		log.Errorf("Could not close %s because %v", name, err)
	}
}
