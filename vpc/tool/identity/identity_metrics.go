package identity

import "go.opencensus.io/stats/view"

func init() {
	if err := view.Register(&view.View{
		Name:        getIdentityLatency.Name(),
		Description: getIdentityLatency.Description(),
		Measure:     getIdentityLatency,
		Aggregation: view.Distribution(),
	},
		&view.View{
			Name:        getIdentityCount.Name(),
			Description: getIdentityCount.Description(),
			Measure:     getIdentityCount,
			Aggregation: view.Count(),
		},

		&view.View{
			Name:        getIdentitySuccess.Name(),
			Description: getIdentitySuccess.Description(),
			Measure:     getIdentitySuccess,
			Aggregation: view.Count(),
		},
	); err != nil {
		panic(err)
	}
}
