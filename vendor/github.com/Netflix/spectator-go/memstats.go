package spectator

import (
	"runtime"
	"time"
)

type memStatsCollector struct {
	registry         *Registry
	bytesAlloc       *Gauge
	allocationRate   *MonotonicCounter
	totalBytesSystem *Gauge
	numLiveObjects   *Gauge
	objectsAllocated *MonotonicCounter
	objectsFreed     *MonotonicCounter

	gcLastPauseTimeValue uint64
	gcPauseTime          *Timer
	gcAge                *Gauge
	gcCount              *MonotonicCounter
	forcedGcCount        *MonotonicCounter
	gcPercCpu            *Gauge
}

func memStats(m *memStatsCollector) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	updateMemStats(m, &mem)
}

func updateMemStats(m *memStatsCollector, mem *runtime.MemStats) {
	m.bytesAlloc.Set(float64(mem.Alloc))
	m.allocationRate.Set(int64(mem.TotalAlloc))
	m.totalBytesSystem.Set(float64(mem.Sys))
	m.numLiveObjects.Set(float64(mem.Mallocs - mem.Frees))
	m.objectsAllocated.Set(int64(mem.Mallocs))
	m.objectsFreed.Set(int64(mem.Frees))

	nanosPause := mem.PauseTotalNs - m.gcLastPauseTimeValue
	m.gcPauseTime.Record(time.Duration(nanosPause))
	m.gcLastPauseTimeValue = mem.PauseTotalNs

	nanos := m.registry.clock.Nanos()
	timeSinceLastGC := nanos - int64(mem.LastGC)
	secondsSinceLastGC := float64(timeSinceLastGC) / 1e9
	m.gcAge.Set(secondsSinceLastGC)

	m.gcCount.Set(int64(mem.NumGC))
	m.forcedGcCount.Set(int64(mem.NumForcedGC))
	m.gcPercCpu.Set(mem.GCCPUFraction * 100)
}

func initializeMemStatsCollector(registry *Registry, mem *memStatsCollector) {
	mem.registry = registry
	mem.bytesAlloc = registry.Gauge("mem.heapBytesAllocated", nil)
	mem.allocationRate = NewMonotonicCounter(registry, "mem.allocationRate", nil)
	mem.totalBytesSystem = registry.Gauge("mem.maxHeapBytes", nil)
	mem.numLiveObjects = registry.Gauge("mem.numLiveObjects", nil)
	mem.objectsAllocated = NewMonotonicCounter(registry, "mem.objectsAllocated", nil)
	mem.objectsFreed = NewMonotonicCounter(registry, "mem.objectsFreed", nil)
	mem.gcPauseTime = registry.Timer("gc.pauseTime", nil)
	mem.gcAge = registry.Gauge("gc.timeSinceLastGC", nil)
	mem.gcCount = NewMonotonicCounter(registry, "gc.count", nil)
	mem.forcedGcCount = NewMonotonicCounter(registry, "gc.forcedCount", nil)
	mem.gcPercCpu = registry.Gauge("gc.cpuPercentage", nil)
}

// Collect memory stats
// https://golang.org/pkg/runtime/#MemStats
func CollectMemStats(registry *Registry) {
	var mem memStatsCollector
	initializeMemStatsCollector(registry, &mem)

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		log := registry.config.Log
		for range ticker.C {
			log.Debugf("Collecting memory stats")
			memStats(&mem)
		}
	}()
}
