package spectator

type Counter struct {
	id    *Id
	count uint64
}

func NewCounter(id *Id) *Counter {
	return &Counter{id, 0}
}

func (c *Counter) MeterId() *Id {
	return c.id
}

func (c *Counter) Measure() []Measurement {
	cnt := swapFloat64(&c.count, 0.0)
	return []Measurement{{c.id.WithDefaultStat("count"), cnt}}
}

func (c *Counter) Increment() {
	addFloat64(&c.count, 1)
}

func (c *Counter) AddFloat(delta float64) {
	if delta > 0.0 {
		addFloat64(&c.count, delta)
	}
}

func (c *Counter) Add(delta int64) {
	if delta > 0 {
		addFloat64(&c.count, float64(delta))
	}
}

func (c *Counter) Count() float64 {
	return loadFloat64(&c.count)
}
