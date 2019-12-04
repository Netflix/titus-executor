package main

import (
	"sync"

	"github.com/Netflix/spectator-go"
	"go.opencensus.io/stats/view"
)

type opencensusDistributionData struct {
	sync.Mutex
	id               *spectator.Id
	distributionData view.DistributionData
}

func newOpencensusDistributionData(id *spectator.Id) *opencensusDistributionData {
	return &opencensusDistributionData{
		id: id,
	}
}

func (d *opencensusDistributionData) MeterId() *spectator.Id { // nolint: golint
	return d.id
}

func (d *opencensusDistributionData) update(data *view.DistributionData) {
	d.Lock()
	defer d.Unlock()
	d.distributionData = *data
}

func (d *opencensusDistributionData) Measure() []spectator.Measurement {
	d.Lock()
	defer d.Unlock()

	cnt := spectator.NewMeasurement(d.id.WithStat("count"), float64(d.distributionData.Count))
	tTime := spectator.NewMeasurement(d.id.WithStat("totalAmount"), (d.distributionData.Sum()))
	mx := spectator.NewMeasurement(d.id.WithStat("max"), (d.distributionData.Max))
	mn := spectator.NewMeasurement(d.id.WithStat("min"), (d.distributionData.Min))
	avg := spectator.NewMeasurement(d.id.WithStat("avg"), (d.distributionData.Mean))

	d.distributionData = view.DistributionData{}

	return []spectator.Measurement{cnt, tTime, avg, mx, mn}
}

type spectatorGoExporter struct {
	registry       *spectator.Registry
	previousValues map[string]int64
}

func newSpectatorGoExporter(registry *spectator.Registry) *spectatorGoExporter {
	return &spectatorGoExporter{
		previousValues: make(map[string]int64),
		registry:       registry,
	}
}

func (s *spectatorGoExporter) opencensusDistributionDataWithId(id *spectator.Id) *opencensusDistributionData { // nolint: golint
	m := s.registry.NewMeter(id, func() spectator.Meter {
		return newOpencensusDistributionData(id)
	})

	d, ok := m.(*opencensusDistributionData)
	if ok {
		return d
	}

	// throw in strict mode
	return newOpencensusDistributionData(id)
}

func (s *spectatorGoExporter) ExportView(vd *view.Data) {
	for _, row := range vd.Rows {
		tags := make(map[string]string, len(row.Tags))
		for idx := range row.Tags {
			tags[row.Tags[idx].Key.Name()] = row.Tags[idx].Value
		}

		id := spectator.NewId(vd.View.Name, tags)
		switch v := row.Data.(type) {
		case *view.DistributionData:
			s.opencensusDistributionDataWithId(id).update(v)
		case *view.CountData:
			key := id.String()
			if prevValue, ok := s.previousValues[key]; ok {
				s.registry.CounterWithId(id).Add(v.Value - prevValue)
				s.previousValues[key] = v.Value
			} else {
				s.registry.CounterWithId(id).Add(v.Value)
				s.previousValues[key] = v.Value
			}
		case *view.SumData:
			s.registry.CounterWithId(id).AddFloat(v.Value)
		case *view.LastValueData:
			s.registry.GaugeWithId(id).Set(v.Value)
		}
	}
}
