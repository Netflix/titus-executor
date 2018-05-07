package api

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Netflix/titus-executor/darion/conf"
	"github.com/Netflix/titus-executor/filesystems"
	"github.com/Netflix/titus-executor/filesystems/xattr"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func init() {
	log.SetLevel(log.DebugLevel)
	// We need to add some attrs to otherlogfile. Xattrs + Git don't work
	if err := xattr.SetXattr("testdata/Titus-fake-container/logs/subdir/otherlogfile", filesystems.StdioAttr, []byte("638")); err != nil {
		panic(err)
	}
	if err := xattr.SetXattr("testdata/Titus-fake-container/logs/subdir/otherlogfile", filesystems.VirtualFilePrefixWithSeparator+"testsuffix", []byte("0,638")); err != nil {
		panic(err)
	}
	filesystems.PotentialStdioNames["otherlogfile"] = struct{}{}
}

func TestListLogs(t *testing.T) {
	verifyFun := func(resp *http.Response, t *testing.T) {

		if resp.StatusCode != 200 {
			t.Fatal("Received non-200 return code: ", resp.StatusCode)
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("Could not read response body: ", err)
		}
		dataStr := string(data)
		if !strings.Contains(dataStr, "stderr") {
			t.Fatal("stderr not found")
		}
		if !strings.Contains(dataStr, "stdout") {
			t.Fatal("stdout not found")
		}
		if !strings.Contains(dataStr, `<a href="/logs/Titus-fake-container?f=subdir/otherlogfile">subdir/otherlogfile</a>`) {
			t.Fatal("base virtual file not found")
		}
		if !strings.Contains(dataStr, `<a href="/logs/Titus-fake-container?f=otherlogfile.testsuffix">otherlogfile.testsuffix</a>`) {
			t.Fatal("extended virtual file found")
		}
	}
	testListLogs(verifyFun, "/listlogs/Titus-fake-container", t)
}

func TestListLogsBadURI(t *testing.T) {
	verifyFun := func(resp *http.Response, t *testing.T) {

		if resp.StatusCode != 404 {
			t.Fatal("Received non-404 return code: ", resp.StatusCode)
		}

	}
	testListLogs(verifyFun, "/listlogs", t)
}

func testListLogs(verifyFunc func(resp *http.Response, t *testing.T), path string, t *testing.T) {
	conf.ContainersHome = "testdata"
	r := http.NewServeMux()
	r.HandleFunc("/listlogs/", ListLogsHandler)
	server := httptest.NewServer(r)
	defer server.Close()

	resp, err := http.Get(server.URL + path)
	if err != nil {
		t.Fatal("Unexpected error")
	}
	defer mustClose(resp.Body)

	verifyFunc(resp, t)

}

func TestReadBaseVirtualFileLogs(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		dataStr := verifyHelper(resp, t)
		if !strings.HasSuffix(dataStr, "\n") {
			t.Fatal("Output truncated")
		}
		if len(dataStr) < 1000 {
			t.Fatal("Output truncated")
		}
		if strings.Count(dataStr, "z") != 1000 {
			t.Fatal("Unexpected number of zs found")
		}
	}

	testReadLogs(verifyFunc, "/logs/Titus-fake-container?f=subdir/otherlogfile", t)
}

func TestReadBaseVirtualFileLogsRange(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		dataStr := verifyHelper(resp, t)
		if !strings.HasSuffix(dataStr, "\n") {
			t.Fatal("Output truncated")
		}
		if len(dataStr) < 800 {
			t.Fatal("Output truncated")
		}
		if strings.Count(dataStr, "z") != 800 {
			t.Fatalf("Unexpected number of zs found: %s", dataStr)
		}
	}

	testReadLogsRange(verifyFunc, "/logs/Titus-fake-container?f=subdir/otherlogfile", "bytes=200-", t)
}

func TestReadVirtualFileLogs(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		dataStr := verifyHelper(resp, t)
		if !strings.HasSuffix(dataStr, "\n") {
			t.Fatal("Output truncated")
		}
		if len(dataStr) < 638 {
			t.Fatal("Output truncated")
		}
		if strings.Count(dataStr, "a") != 637 {
			t.Fatal("Unexpected number of bs found")
		}
	}

	testReadLogs(verifyFunc, "/logs/Titus-fake-container?f=subdir/otherlogfile.testsuffix", t)
}

func TestReadVirtualFileLogsRange(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		dataStr := verifyHelper(resp, t)
		if !strings.HasSuffix(dataStr, "\n") {
			t.Fatal("Output truncated")
		}
		if len(dataStr) < 437 {
			t.Fatal("Output truncated")
		}
		if strings.Count(dataStr, "a") != 437 {
			t.Fatal("Unexpected number of as found")
		}
	}

	testReadLogsRange(verifyFunc, "/logs/Titus-fake-container?f=subdir/otherlogfile.testsuffix", "bytes=200-", t)
}

func TestReadMissingVirtualFileLogs(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("Could not read response body: ", err)
		}
		dataStr := string(data)
		if resp.StatusCode != 404 {
			t.Fatalf("Received non-404 return code (%d), with error: %s", resp.StatusCode, dataStr)
		}
		if !strings.Contains(dataStr, "attribute not found") &&
			!strings.Contains(dataStr, "no data available") &&
			!strings.Contains(dataStr, "Virtual Log file not found") {
			t.Fatal("Invalid error response: ", dataStr)
		}
	}

	testReadLogs(verifyFunc, "/logs/Titus-fake-container?f=subdir/otherlogfile.nonExistentSuffix", t)
}

func TestReadLogs(t *testing.T) {
	testReadLogs(verifyStdout, "/logs/Titus-fake-container?f=stdout", t)
}

func TestReadLogsRange(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		dataStr := verifyHelper(resp, t)
		if !strings.HasSuffix(dataStr, "\n") {
			t.Fatal("Output truncated")
		}
		if len(dataStr) != 15 {
			t.Fatalf("Output wrong length")
		}
	}
	testReadLogsRange(verifyFunc, "/logs/Titus-fake-container?f=stdout", "bytes=5-", t)
}

func TestReadLogsOutOfRange(t *testing.T) {
	verifyFunc := func(resp *http.Response, t *testing.T) {
		if resp.StatusCode != 416 {
			t.Fatal("Received non-416 return code: ", resp.StatusCode)
		}
	}
	testReadLogsRange(verifyFunc, "/logs/Titus-fake-container?f=stdout", "bytes=100000-", t)
}

func TestReadLogsDefaultFile(t *testing.T) {
	testReadLogs(verifyStdout, "/logs/Titus-fake-container", t)
}

func TestReadLogsMissingFile(t *testing.T) {
	verifyFun := func(resp *http.Response, t *testing.T) {
		if resp.StatusCode != 404 {
			t.Fatal("Received non-404 return code: ", resp.StatusCode)
		}
	}
	testReadLogs(verifyFun, "/logs/Titus-fake-container?f=missing", t)
}

func TestReadLogsMissingContainer(t *testing.T) {
	verifyFun := func(resp *http.Response, t *testing.T) {
		if resp.StatusCode != 404 {
			t.Fatal("Received non-404 return code: ", resp.StatusCode)
		}
	}
	testReadLogs(verifyFun, "/logs/Titus-fake-container-missing?f=missing", t)
}

func verifyHelper(resp *http.Response, t *testing.T) string {
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Could not read response body: ", err)
	}
	dataStr := string(data)
	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		t.Fatalf("Received non-200 return code (%d), with error: %s", resp.StatusCode, dataStr)
	}
	return string(data)
}

func verifyStdout(resp *http.Response, t *testing.T) {
	dataStr := verifyHelper(resp, t)
	if !strings.Contains(dataStr, "test") {
		t.Fatal("Content not found")
	}
	if !strings.Contains(dataStr, "file") {
		t.Fatal("Content not found")
	}
}

func testReadLogsRange(verifyFunc func(resp *http.Response, t *testing.T), path string, rangeHeader string, t *testing.T) {
	conf.ContainersHome = "testdata"
	r := http.NewServeMux()
	r.HandleFunc("/logs/", LogHandler)
	server := httptest.NewServer(r)
	defer server.Close()

	client := &http.Client{}
	req, err := http.NewRequest("GET", server.URL+path, nil)
	assert.NoError(t, err)

	if rangeHeader != "" {
		req.Header.Add("Range", rangeHeader)
	}

	resp, e := client.Do(req)
	assert.NoError(t, e)
	defer mustClose(resp.Body)

	verifyFunc(resp, t)
}

func testReadLogs(verifyFunc func(resp *http.Response, t *testing.T), path string, t *testing.T) {
	testReadLogsRange(verifyFunc, path, "", t)
}

func mustClose(f io.Closer) {
	if err := f.Close(); err != nil {
		panic(err)
	}
}
