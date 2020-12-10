package kubelet

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	log "github.com/sirupsen/logrus"
)

// VolumeLogViewer is a webserver with handlers for the common logviewer apis configured around the specified volume
type VolumeLogViewer struct {
	Volume string
}

type tmplData struct {
	PodID    string
	FileList []string
}

var listLogsTemplate = template.Must(template.New("listLogs").Parse(`
<!DOCTYPE html>
<html>
	<head>
	</head>
	<body>
		<h4>Log files for {{.PodID}}</h4>
		<ul>
			{{range .FileList}}
				<li><a href="/logs/{{$.PodID}}?f={{.}}">{{.}}</a></li>
			{{end}}
		</ul>
	</body>
</html>
`))

// ListLogs enumerates all the logs in the shared volume
func (v *VolumeLogViewer) ListLogs(w http.ResponseWriter, r *http.Request) {
	podID := getPodID(r.URL.Path)

	fileList := []string{}
	err := filepath.Walk(v.Volume, func(path string, f os.FileInfo, err error) error {
		if f != nil && !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})

	if err != nil {
		http.Error(w, "No Log files are present", http.StatusNotFound)
		return
	}

	t := tmplData{
		PodID:    podID,
		FileList: fileList,
	}

	w.Header().Set("Content-Type", "text/html")
	err = listLogsTemplate.Execute(w, t)
	if err != nil {
		log.Error("Unable to list logs, error executing template:", err)
		return
	}
}

func getPodID(path string) string {
	splitPath := filepath.SplitList(path)
	if len(splitPath) < 2 {
		return ""
	}
	return splitPath[1]
}

// Log returns the contents of a specific log file
func (v *VolumeLogViewer) Log(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("f")

	filePath, err := securejoin.SecureJoin(v.Volume, fileName)
	log.Infof("Joined log file %s and %s", v.Volume, fileName)
	if err != nil {
		log.WithError(err).Error("Unable to build secure path")
		http.Error(w, "Cannot build log file path: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	fout, err := os.Open(filePath)
	if os.IsNotExist(err) {
		http.Error(w, fmt.Sprint("Error reading file: ", err), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprint("Error reading file: ", err), http.StatusServiceUnavailable)
		return
	}
	defer shouldClose(fout)

	http.ServeContent(w, r, fout.Name(), time.Now(), fout)
}

func shouldClose(file *os.File) {
	name := file.Name()
	if err := file.Close(); err != nil {
		log.Errorf("Could not close  %s because %v", name, err)
	}
}

// AttachHandlers will bind the handlers to the canonical paths to fulfill the interface
func (v *VolumeLogViewer) AttachHandlers(mux *http.ServeMux) *http.ServeMux {
	mux.HandleFunc("/listlogs/", v.ListLogs)
	mux.HandleFunc("/logs/", v.Log)
	return mux
}
