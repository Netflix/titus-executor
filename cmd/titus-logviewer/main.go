package main

import (
	"net/http"

	"github.com/Netflix/titus-executor/logsutil"
	"github.com/Netflix/titus-executor/logviewer/api"
	"github.com/Netflix/titus-executor/logviewer/conf"

	log "github.com/sirupsen/logrus"
)

func pingHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := w.Write([]byte("pong")); err != nil {
		log.Error("Unable to respond with pong on ping handler: ", err)
	}
}

func main() {
	logsutil.MaybeSetupLoggerIfOnJournaldAvailable()
	log.Println("Titus logviewer is starting")
	r := newMux()
	if err := http.ListenAndServe(":8004", r); err != nil {
		log.Error("Error: HTTP ListenAndServe: ", err)
	}
}

func newMux() *http.ServeMux {
	r := http.NewServeMux()

	r.HandleFunc("/ping", pingHandler)

	if conf.ProxyMode {
		api.RegisterProxyHandlers(r)
		return r
	}

	api.RegisterHandlers(r)
	return r
}
