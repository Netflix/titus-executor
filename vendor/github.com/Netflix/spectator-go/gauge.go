package spectator

import "math"

type Gauge struct {
	id        *Id
	valueBits uint64
}

func NewGauge(id *Id) *Gauge {
	return &Gauge{id, math.Float64bits(math.NaN())}
}

func (g *Gauge) MeterId() *Id {
	return g.id
}

func (g *Gauge) Measure() []Measurement {
	return []Measurement{{g.id.WithDefaultStat("gauge"), swapFloat64(&g.valueBits, math.NaN())}}
}

func (g *Gauge) Set(value float64) {
	storeFloat64(&g.valueBits, value)
}

func (g *Gauge) Get() float64 {
	return loadFloat64(&g.valueBits)
}
