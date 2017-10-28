package executor

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/Netflix/titus-executor/models"
	log "github.com/sirupsen/logrus"

	"context"
	"net/http/pprof"
)

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Printf("Error writting healthcheck %v\n", err)
	}
}

func buildCurrentState(e *Executor) *models.CurrentState {
	// There is a race condition here.... :(
	// We have concurrent map access and modification without holding a lock
	// This state management needs to be refactored
	tasks := map[string]string{}
	e.Lock()
	defer e.Unlock()
	for tid, state := range e.taskStates {
		tasks[tid] = state.String()
	}
	return &models.CurrentState{Tasks: tasks}
}

func (executor *Executor) stateHandler(w http.ResponseWriter, r *http.Request) {
	currentState := buildCurrentState(executor)
	outBytes, err := json.Marshal(currentState)
	if err == nil {
		w.Header().Add("Content-Type", "application/json")
		if _, err = w.Write(outBytes); err != nil {
			log.Printf("Error writting stateHandler in httpserver %v\n", err)
		}
	} else {
		log.Warning("Unable to serialize JSON response: ", err)
		w.WriteHeader(500)
	}
}

func (executor *Executor) setupServeMux() {
	executor.serveMux = http.NewServeMux()
	executor.serveMux.HandleFunc("/healthcheck", healthCheckHandler)
	executor.serveMux.HandleFunc("/get-current-state", executor.stateHandler)
	executor.serveMux.HandleFunc("/debug/pprof/", http.HandlerFunc(pprof.Index))
	executor.serveMux.HandleFunc("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	executor.serveMux.HandleFunc("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	executor.serveMux.HandleFunc("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	executor.serveMux.HandleFunc("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
}

/*
 The permanent HTTP server on port 8005 below exists, but this binds to an OS chosen port, so it doesn't last
 between invocation, and executions of the executor. It is exposed by the titus.executor.http.listener.address
 label on the Docker container. Then things interested in it can come and fetch metadata about the executor.
 We want to choose a different one every time so we can ensure that there is a clear mapping

 Eventually, this port should be chosen by Mesos / the scheduler to preserve the end-to-end metadata, but this
 works for now.
*/
func (executor *Executor) setupEphemeralHTTPServer() {
	// Must have serverMux setup prior to calling this
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("Could not start ephemeral listener")
	}
	log.Info("Setting up ephemeral listener on: ", listener.Addr().String())
	executor.ephemeralHTTPListener = listener
	ctx, cancel := context.WithCancel(executor.ctx)
	errChan := make(chan error)
	go func() {
		// No need to put cancel here, because it'll always cascade to the goroutine below
		errChan <- http.Serve(listener, executor.serveMux)
	}()
	go func() {
		defer cancel()
		defer func() {
			if err2 := listener.Close(); err2 != nil {
				log.Warning("Error closing listener: ", err2)
			}
		}()

		select {
		case err := <-errChan:
			log.Fatal("Error setting up HTTP Server: ", err)
		case <-ctx.Done():
			log.Info("Shutting down ephemeral HTTP listener")
		}
	}()
}

// GetServeMux return's the executor's servemux, in case an external user wants to use it in their own server
func (executor *Executor) GetServeMux() *http.ServeMux {
	return executor.serveMux
}
