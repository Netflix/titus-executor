package spectator

import (
	"sync/atomic"
)

type DistributionSummary struct {
	id          *Id
	count       int64
	totalAmount int64
	totalSqBits uint64
	max         int64
}

func NewDistributionSummary(id *Id) *DistributionSummary {
	return &DistributionSummary{id, 0, 0, 0, 0}
}

func (d *DistributionSummary) MeterId() *Id {
	return d.id
}

func (d *DistributionSummary) Record(amount int64) {
	if amount >= 0 {
		atomic.AddInt64(&d.count, 1)
		atomic.AddInt64(&d.totalAmount, amount)
		addFloat64(&d.totalSqBits, float64(amount)*float64(amount))
		updateMax(&d.max, amount)
	}
}

func (d *DistributionSummary) Count() int64 {
	return atomic.LoadInt64(&d.count)
}

func (d *DistributionSummary) TotalAmount() int64 {
	return atomic.LoadInt64(&d.totalAmount)
}

func (d *DistributionSummary) Measure() []Measurement {
	cnt := Measurement{d.id.WithStat("count"), float64(atomic.SwapInt64(&d.count, 0))}
	tTime := Measurement{d.id.WithStat("totalAmount"), float64(atomic.SwapInt64(&d.totalAmount, 0))}
	tSq := Measurement{d.id.WithStat("totalOfSquares"), swapFloat64(&d.totalSqBits, 0.0)}
	mx := Measurement{d.id.WithStat("max"), float64(atomic.SwapInt64(&d.max, 0))}

	return []Measurement{cnt, tTime, tSq, mx}
}
