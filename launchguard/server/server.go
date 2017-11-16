package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/launchguard/client"
	"github.com/Netflix/titus-executor/launchguard/core"
	"github.com/gorilla/mux"
	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
)

type cleanupRoutine struct {
	once          sync.Once
	heartbeatChan chan struct{}
}

type launchGuardContainer struct {
	sync.RWMutex
	lg            *core.LaunchGuard
	cleanupEvents map[string]*cleanupRoutine
}

type LaunchGuardServer struct {
	sync.Mutex
	router       *mux.Router
	m            metrics.Reporter
	launchguards map[string]*launchGuardContainer
}

func NewLaunchGuardServer(m metrics.Reporter) *LaunchGuardServer {
	lgs := &LaunchGuardServer{
		m:            m,
		launchguards: make(map[string]*launchGuardContainer),
	}
	lgs.router = mux.NewRouter()
	//
	lgs.router.HandleFunc("/launchguard/{key}/launchevent", lgs.newLaunchEvent).Methods("GET")
	lgs.router.HandleFunc("/launchguard/{key}/cleanupevent/{id}", lgs.newCleanupEvent).Methods("PUT")
	lgs.router.HandleFunc("/launchguard/{key}/cleanupevent/{id}/heartbeat", lgs.heartBeatCleanupEvent).Methods("POST")
	lgs.router.HandleFunc("/launchguard/{key}/cleanupevent/{id}", lgs.removeCleanupEvent).Methods("DELETE")

	return lgs
}

func (lgs *LaunchGuardServer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	id := uuid.New()
	log.WithField("id", id).WithField("url", req.URL).WithField("method", req.Method).Debug("Starting")
	lgs.router.ServeHTTP(resp, req)
	log.WithField("id", id).WithField("url", req.URL).Debug("Stopping")

}

func (lgs *LaunchGuardServer) getLaunchGuardContainer(key string) *launchGuardContainer {
	lgs.Lock()
	defer lgs.Unlock()
	if _, ok := lgs.launchguards[key]; !ok {
		lgs.launchguards[key] = &launchGuardContainer{
			lg:            core.NewLaunchGuard(lgs.m),
			cleanupEvents: make(map[string]*cleanupRoutine),
		}
	}
	return lgs.launchguards[key]
}

func (lgs *LaunchGuardServer) newLaunchEvent(resp http.ResponseWriter, req *http.Request) {
	lgc := lgs.getLaunchGuardContainer(mux.Vars(req)["key"])

	log.Info("X")
	launchEvent := core.NewLaunchEvent(lgc.lg)
	log.Info("Y")

	resp.WriteHeader(http.StatusOK)
	resp.(http.Flusher).Flush()
	log.Info("Z")

	select {
	case <-launchEvent.Launch():
		_, _ = resp.Write([]byte("launch"))
	case <-req.Context().Done():
		_, _ = resp.Write([]byte("timeout"))
	}
}

func (lgs *LaunchGuardServer) newCleanupEvent(resp http.ResponseWriter, req *http.Request) {
	lgc := lgs.getLaunchGuardContainer(mux.Vars(req)["key"])
	lgc.Lock()
	defer lgc.Unlock()
	id := mux.Vars(req)["id"]
	lgc.cleanupEvents[id] = newCleanupRoutine(lgc, id)
	resp.WriteHeader(http.StatusCreated)

}

func (lgs *LaunchGuardServer) heartBeatCleanupEvent(resp http.ResponseWriter, req *http.Request) {
	lgc := lgs.getLaunchGuardContainer(mux.Vars(req)["key"])
	lgc.Lock()
	defer lgc.Unlock()
	id := mux.Vars(req)["id"]
	if myCleanupRoutine, ok := lgc.cleanupEvents[id]; ok {
		myCleanupRoutine.heartBeat()
		resp.WriteHeader(http.StatusAccepted)
	} else {
		resp.WriteHeader(http.StatusNotFound)
	}
}

func (lgs *LaunchGuardServer) removeCleanupEvent(resp http.ResponseWriter, req *http.Request) {
	lgc := lgs.getLaunchGuardContainer(mux.Vars(req)["key"])
	lgc.Lock()
	defer lgc.Unlock()
	id := mux.Vars(req)["id"]
	if myCleanupRoutine, ok := lgc.cleanupEvents[id]; ok {
		myCleanupRoutine.once.Do(func() {
			close(myCleanupRoutine.heartbeatChan)
		})
		resp.WriteHeader(http.StatusOK)
	} else {
		resp.WriteHeader(http.StatusNotFound)
	}
}

func newCleanupRoutine(lgc *launchGuardContainer, id string) *cleanupRoutine {
	cr := &cleanupRoutine{
		heartbeatChan: make(chan struct{}),
	}
	waitCh := make(chan struct{})
	go cr.run(lgc, id, waitCh)
	<-waitCh
	return cr
}

func (cr *cleanupRoutine) heartBeat() {
	select {
	case cr.heartbeatChan <- struct{}{}:
	case <-time.After(100 * time.Millisecond):
		log.Fatal("Heartbeat channel blocked")
	}
}

func (cr *cleanupRoutine) run(lgc *launchGuardContainer, id string, waitCh chan struct{}) {
	log.WithField("id", id).Debug("Cleanup event initializing")
	defer log.WithField("id", id).Debug("Cleanup event cleaning up")

	ctx, cancel := context.WithTimeout(context.Background(), client.MaxLaunchTime)
	defer cancel()
	cleanupEvent := core.NewRealCleanUpEvent(ctx, lgc.lg)
	defer cleanupEvent.Done()
	close(waitCh)

	timer := time.NewTimer(client.RefreshWindow * 3)
	defer timer.Stop()
	defer func() {
		lgc.Lock()
		defer lgc.Unlock()
		delete(lgc.cleanupEvents, id)
	}()

	for {
		select {
		case <-timer.C:
			log.WithField("id", id).Warning("Launchguard cleanup expired")
		case _, ok := <-cr.heartbeatChan:
			if ok {
				timer.Reset(client.RefreshWindow * 3)
			} else {
				return
			}
		}
	}
}
