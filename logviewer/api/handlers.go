package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/filesystems/xattr"
	"github.com/Netflix/titus-executor/logviewer/conf"
	securejoin "github.com/cyphar/filepath-securejoin"
	log "github.com/sirupsen/logrus"
)

// LogHandler is an HTTP handler that handles the /logs/:containerid/... endpoint, and fetches a file on the client's behalf
func LogHandler(w http.ResponseWriter, r *http.Request) {
	containerID, err := containerIDFromURL(r.URL.Path, logsExp)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	fileName := r.URL.Query().Get("f")
	if fileName == "" {
		fileName = "stdout"
	}
	addDownloadHeader := r.URL.Query().Get("download") == "true"

	logHandler(w, r, containerID, fileName, addDownloadHeader)
}

func logHandler(w http.ResponseWriter, r *http.Request, containerID, fileName string, addDownloadHeader bool) {
	containerLogsRoot := buildLogLocationBase(containerID)

	filePath, err := securejoin.SecureJoin(containerLogsRoot, fileName)
	log.Infof("Joined log file %s and filename %s to %s (container ID: %s)", containerLogsRoot, fileName, filePath, containerID)
	if err != nil {
		log.WithError(err).Error("Unable to build secure path")
		http.Error(w, "Cannot build log file path: "+err.Error(), 503)
		return
	}
	fout, err := os.Open(filePath) // nolint: gosec
	if os.IsNotExist(err) {
		err = maybeVirtualFileStdioLogHandler(w, r, containerID, fileName)
		if err != nil {
			http.Error(w, fmt.Sprint("Error reading file: ", err), 404)
		}
		return
	} else if err != nil {
		log.Errorf("File %s could not be opened - %v", fileName, err.Error())
		http.Error(w, "No Log files are present", 404)
		return
	}
	defer shouldClose(fout)

	if addDownloadHeader {
		basename := filepath.Base(fileName)
		quoteEscapedBasename := strings.ReplaceAll(basename, `"`, `\"`)
		// This Content-Disposition header tells a browser to pop up the "Save As" dialog
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition
		w.Header().Set("Content-Disposition", `attachment; filename="`+quoteEscapedBasename+`"`)
	}

	// Logging the error should happen inside of the function itself
	err = logHandlerWithFile(w, r, fout)
	if err != nil {
		http.Error(w, fmt.Sprint("Error reading file: ", err), 404)

	}
}

type virtualFilemap struct {
	diskFileName string
	xattrKey     string
}

func buildVirtualFileMapping(containerID, uriFileName string) map[string]virtualFilemap {
	virtualFilemapping := map[string]virtualFilemap{}
	for _, potentialStdioName := range filesystems.PotentialStdioNames(path.Dir(uriFileName)) {
		// Is the URL filename in this "hashset"?
		// In other words, does the path we are looking at start with stdout/err ?
		if !strings.HasPrefix(path.Base(uriFileName), potentialStdioName) {
			continue
		}

		diskFileName := filepath.Join(buildLogLocationBase(containerID), path.Dir(uriFileName), potentialStdioName)
		xattrList, err := xattr.ListXattrs(diskFileName)
		if err != nil {
			log.Warningf("Could not fetch xattr list for %s, because %v, not adding to virtual file table", diskFileName, err)
			continue
		}
		for xattrKey := range xattrList {
			if strings.HasPrefix(xattrKey, filesystems.VirtualFilePrefixWithSeparator) {
				virtualFileSuffix := strings.TrimPrefix(xattrKey, filesystems.VirtualFilePrefixWithSeparator)
				virtualFileName := strings.Join([]string{path.Base(diskFileName), virtualFileSuffix}, ".")
				virtualFilemapping[virtualFileName] = virtualFilemap{diskFileName, xattrKey}
			}
		}
	}
	return virtualFilemapping
}

func maybeVirtualFileStdioLogHandler(w http.ResponseWriter, r *http.Request, containerID, uriFileName string) error {
	virtualFilemapping := buildVirtualFileMapping(containerID, uriFileName)

	mapping, ok := virtualFilemapping[path.Base(uriFileName)]
	if !ok {
		log.WithField("uriFileName", uriFileName).WithField("virtualFilemapping", virtualFilemapping).Debug("Virtual File Not Found")
		return errors.New("Virtual Log file not found")
	}

	fout, err := os.Open(mapping.diskFileName)
	if err != nil {
		log.Errorf("File %s could not be opened - %v", mapping.diskFileName, err)
		return err
	}
	defer shouldClose(fout)

	offset, length, err := filesystems.FetchStartAndLen(mapping.xattrKey, fout)
	if err != nil {
		log.Errorf("Error getting virtual offset for %s -- %s because %v", fout.Name(), mapping.xattrKey, err)
		return err
	}

	csr := io.NewSectionReader(fout, offset, length)
	http.ServeContent(w, r, fout.Name(), time.Now(), csr)
	return nil
}

func logHandlerWithFile(w http.ResponseWriter, r *http.Request, fout *os.File) error {

	if CheckFDForStdio(fout) {
		return stdioLogHandlerWithFile(w, r, fout)
	}
	http.ServeContent(w, r, fout.Name(), time.Now(), fout)
	return nil
}

// CheckFDForStdio determines whether the file at the fd is one written by tini as a stdio rotator
func CheckFDForStdio(file *os.File) bool {
	if _, err := xattr.FGetXattr(file, filesystems.StdioAttr); err == xattr.ENOATTR {
		return false
	} else if os.IsNotExist(err) {
		return false
	} else if err != nil {
		log.Errorf("Unable to fetch stdio attr from file %s because: %v", file.Name(), err)
	}

	return true
}

func stdioLogHandlerWithFile(w http.ResponseWriter, r *http.Request, fout *os.File) error {
	// Do stdio handler path
	currentOffset, err := filesystems.GetCurrentOffset(fout)
	if err != nil {
		log.Errorf("Error getting current offest for %s because %v", fout.Name(), err)
		return err
	}

	size, e := fout.Seek(0, io.SeekEnd)
	if e != nil {
		log.Errorf("Error getting size for %s because %v", fout.Name(), e)
		return err
	}

	size = size - currentOffset
	csr := io.NewSectionReader(fout, currentOffset, size)
	http.ServeContent(w, r, fout.Name(), time.Now(), csr)
	return nil
}

// ListLogsHandler handles the /listlogs/:containerid/... endpoint and enumerates the files, and subdirectories of /logs for a given container
func ListLogsHandler(w http.ResponseWriter, r *http.Request) {
	containerID, err := containerIDFromURL(r.URL.Path, listLogsExp)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	dirName := buildLogLocationBase(containerID)

	fileList := []string{}
	err = filepath.Walk(dirName, func(path string, f os.FileInfo, err error) error {
		if f != nil && !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})

	if err != nil {
		log.Println(err)
		http.Error(w, "No Log files are present", 404)
		return
	}

	w.Header().Set("Content-Type", "text/html")

	err = writeResponse(w, containerID, fileList)
	if err != nil {
		log.Error("Unable to list logs, error while writing response: ", err)
	}
}

func writeResponse(w io.Writer, containerID string, fileList []string) error {
	if _, err := fmt.Fprintf(w, "<html>"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "<h4>Log files for %v</h4>", containerID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "<ul>"); err != nil {
		return err
	}

	for _, fileName := range fileList {
		if filesystems.CheckFileForStdio(fileName) {
			if err := writeStdioVirtualLinks(containerID, fileName, w); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, buildLink(containerID, fileName)); err != nil { //nolint:staticcheck
				return err
			}
		}
	}

	_, err := fmt.Fprintf(w, "</ul>")

	return err
}

func buildLogLocationBase(containerID string) string {
	if conf.RunningInContainer {
		return "/logs"
	}

	return filepath.Join(conf.ContainersHome, containerID, "/logs")
}

func buildLink(containerID, fileName string) string {
	base := buildLogLocationBase(containerID)
	relFilePath, err := filepath.Rel(base, fileName)
	if err == nil {
		return fmt.Sprintf("<li><a href=\"/logs/%s?f=%s\">%s</a></li>\n", containerID, relFilePath, relFilePath)
	}
	return ""
}

func writeStdioVirtualLinks(containerID, fileName string, w io.Writer) error {
	// First build the "normal" file
	base := buildLogLocationBase(containerID)
	relFilePath, err := filepath.Rel(base, fileName)
	if err == nil {
		_, err = fmt.Fprintf(w, "<li><a href=\"/logs/%s?f=%s\">%s</a></li>\n", containerID, relFilePath, relFilePath)
		if err != nil {
			return err
		}
	}
	// Then build the virtual files
	xattrList, err := xattr.ListXattrs(fileName)
	if err != nil {
		log.Warningf("Could not fetch xattr list for %s, because %v, not listing virtual files", fileName, err)
		return nil
	}
	for xattrKey := range xattrList {
		if !strings.HasPrefix(xattrKey, filesystems.VirtualFilePrefixWithSeparator) {
			continue
		}
		virtualFileSuffix := strings.TrimPrefix(xattrKey, filesystems.VirtualFilePrefixWithSeparator)
		virtualFileName := strings.Join([]string{path.Base(fileName), virtualFileSuffix}, ".")
		_, err = fmt.Fprintf(w, `<li><a href="/logs/%s?f=%s">%s</a></li>`, containerID, virtualFileName, virtualFileName)
		if err != nil {
			return err
		}
	}
	return nil
}

func shouldClose(file *os.File) {
	name := file.Name()
	if err := file.Close(); err != nil {
		log.Errorf("Could not close %s because %v", name, err)
	}
}

func RegisterHandlers(r *http.ServeMux) {
	r.HandleFunc("/logs/", LogHandler)
	r.HandleFunc("/listlogs/", ListLogsHandler)
}
