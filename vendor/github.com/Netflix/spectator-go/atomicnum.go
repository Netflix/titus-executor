package spectator

import (
	"math"
	"sync/atomic"
)

func addFloat64(addr *uint64, delta float64) {
	for {
		old := loadFloat64(addr)
		newVal := old + delta
		if atomic.CompareAndSwapUint64(
			addr,
			math.Float64bits(old),
			math.Float64bits(newVal),
		) {
			break
		}
	}
}

func updateMax(addr *int64, v int64) {
	m := atomic.LoadInt64(addr)
	for v > m {
		if atomic.CompareAndSwapInt64(addr, m, v) {
			break
		}
		m = atomic.LoadInt64(addr)
	}
}

func swapFloat64(addr *uint64, newVal float64) float64 {
	return math.Float64frombits(atomic.SwapUint64(addr, math.Float64bits(newVal)))
}

func loadFloat64(addr *uint64) float64 {
	return math.Float64frombits(atomic.LoadUint64(addr))
}

func storeFloat64(addr *uint64, newVal float64) {
	atomic.StoreUint64(addr, math.Float64bits(newVal))
}
