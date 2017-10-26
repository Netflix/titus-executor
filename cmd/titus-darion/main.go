package main

import (
	"net/http"

	"github.com/Netflix/titus-executor/darion/api"
	"github.com/Netflix/titus-executor/logsutil"
	log "github.com/sirupsen/logrus"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("pong")); err != nil {
		log.Error("Unable to respond with pong on ping handler: ", err)
	}
}

func main() {
	logsutil.MaybeSetupLoggerIfUnderSystemd()
	log.Println("Darion is starting")
	r := newMux()
	if err := http.ListenAndServe(":8004", r); err != nil {
		log.Error("Error: HTTP ListenAndServe: ", err)
	}
}

func newMux() *http.ServeMux {
	r := http.NewServeMux()
	r.HandleFunc("/ping", pingHandler)
	r.HandleFunc("/logs/", api.LogHandler)
	r.HandleFunc("/listlogs/", api.ListLogsHandler)
	return r
}
