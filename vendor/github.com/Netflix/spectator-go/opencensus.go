package spectator

import (
	"sync"

	"go.opencensus.io/stats/view"
)

type opencensusDistributionData struct {
	sync.Mutex
	id               *Id
	distributionData view.DistributionData
}

func newOpencensusDistributionData(id *Id) *opencensusDistributionData {
	return &opencensusDistributionData{
		id: id,
	}
}

func (d *opencensusDistributionData) MeterId() *Id {
	return d.id
}

func (d *opencensusDistributionData) update(data *view.DistributionData) {
	d.Lock()
	defer d.Unlock()
	d.distributionData = *data
}

func (d *opencensusDistributionData) Measure() []Measurement {
	d.Lock()
	defer d.Unlock()

	cnt := Measurement{d.id.WithStat("count"), float64(d.distributionData.Count)}
	tTime := Measurement{d.id.WithStat("totalAmount"), float64(d.distributionData.Sum())}
	mx := Measurement{d.id.WithStat("max"), float64(d.distributionData.Max)}
	mn := Measurement{d.id.WithStat("min"), float64(d.distributionData.Min)}
	avg := Measurement{d.id.WithStat("avg"), float64(d.distributionData.Mean)}

	d.distributionData = view.DistributionData{}

	return []Measurement{cnt, tTime, avg, mx, mn}
}
