package spectator

import (
	"runtime"
	"time"
)

type sysStatsCollector struct {
	registry      *Registry
	curOpen       *Gauge
	maxOpen       *Gauge
	numGoroutines *Gauge
}

func goRuntimeStats(s *sysStatsCollector) {
	s.numGoroutines.Set(float64(runtime.NumGoroutine()))
}

// Collects system stats: current/max file handles, number of goroutines
func CollectSysStats(registry *Registry) {
	var s sysStatsCollector
	s.registry = registry
	s.maxOpen = registry.Gauge("fh.allocated", nil)
	s.curOpen = registry.Gauge("fh.max", nil)
	s.numGoroutines = registry.Gauge("go.numGoroutines", nil)

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		log := registry.config.Log
		for range ticker.C {
			log.Debugf("Collecting system stats")
			fdStats(&s)
			goRuntimeStats(&s)
		}
	}()
}

// Starts the collection of memory and file handle metrics
func CollectRuntimeMetrics(registry *Registry) {
	CollectMemStats(registry)
	CollectSysStats(registry)
}
