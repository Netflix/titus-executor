package spectator

import "sync/atomic"

type MonotonicCounter struct {
	registry *Registry
	id       *Id
	value    int64
	counter  *Counter
}

func NewMonotonicCounter(registry *Registry, name string, tags map[string]string) *MonotonicCounter {
	return NewMonotonicCounterWithId(registry, NewId(name, tags))
}

func NewMonotonicCounterWithId(registry *Registry, id *Id) *MonotonicCounter {
	return &MonotonicCounter{registry, id, 0, nil}
}

func (c *MonotonicCounter) Set(amount int64) {
	prev := atomic.LoadInt64(&c.value)
	if prev > 0 {
		if c.counter == nil {
			c.counter = c.registry.CounterWithId(c.id)
		}
		delta := amount - prev
		if delta >= 0 {
			c.counter.Add(delta)
		}
	}
	atomic.StoreInt64(&c.value, amount)
}

func (c *MonotonicCounter) Count() int64 {
	return atomic.LoadInt64(&c.value)
}
