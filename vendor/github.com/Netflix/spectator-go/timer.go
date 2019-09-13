package spectator

import (
	"sync/atomic"
	"time"
)

type Timer struct {
	id             *Id
	count          int64
	totalTime      int64
	totalOfSquares uint64
	max            int64
}

func NewTimer(id *Id) *Timer {
	return &Timer{id, 0, 0, 0, 0}
}

func (t *Timer) MeterId() *Id {
	return t.id
}

func (t *Timer) Record(amount time.Duration) {
	if amount >= 0 {
		atomic.AddInt64(&t.count, 1)
		atomic.AddInt64(&t.totalTime, int64(amount))
		addFloat64(&t.totalOfSquares, float64(amount)*float64(amount))
		updateMax(&t.max, int64(amount))
	}
}

func (t *Timer) Count() int64 {
	return atomic.LoadInt64(&t.count)
}

func (t *Timer) TotalTime() time.Duration {
	return time.Duration(atomic.LoadInt64(&t.totalTime))
}

func (t *Timer) Measure() []Measurement {
	cnt := Measurement{t.id.WithStat("count"), float64(atomic.SwapInt64(&t.count, 0))}
	totalNanos := atomic.SwapInt64(&t.totalTime, 0)
	tTime := Measurement{t.id.WithStat("totalTime"), float64(totalNanos) / 1e9}
	totalSqNanos := swapFloat64(&t.totalOfSquares, 0.0)
	tSq := Measurement{t.id.WithStat("totalOfSquares"), totalSqNanos / 1e18}
	maxNanos := atomic.SwapInt64(&t.max, 0)
	mx := Measurement{t.id.WithStat("max"), float64(maxNanos) / 1e9}

	return []Measurement{cnt, tTime, tSq, mx}
}
