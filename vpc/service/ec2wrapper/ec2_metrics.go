package ec2wrapper

import (
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

func init() {
	registerMetrics([]tag.Key{}, getInterfaceMs, getInterfaceCount, getInterfaceSuccess, invalidateInstanceFromCache, storedInstanceInCache, getInstanceFromCache, getInstanceFromCacheSuccess, getInstanceMs, getInstanceCount, getInstanceSuccess, cachedInstancesFreed)
	if err := view.Register(&view.View{
		Name:        batchWaitPeriod.Name(),
		Description: batchWaitPeriod.Description(),
		Measure:     batchWaitPeriod,
		Aggregation: view.Distribution(),
	},
		&view.View{
			Name:        batchSize.Name(),
			Description: batchSize.Description(),
			Measure:     batchSize,
			Aggregation: view.Distribution(),
		},
		&view.View{
			Name:        batchLatency.Name(),
			Description: batchLatency.Description(),
			Measure:     batchLatency,
			Aggregation: view.Distribution(),
		},
		&view.View{
			Name:        cachedInstances.Name(),
			Description: cachedInstances.Description(),
			TagKeys:     []tag.Key{keyRegion, keyAccountID},
			Measure:     cachedInstances,
			Aggregation: view.LastValue(),
		},
		&view.View{
			Name:        cachedSubnets.Name(),
			Description: cachedSubnets.Description(),
			TagKeys:     []tag.Key{keyRegion, keyAccountID},
			Measure:     cachedSubnets,
			Aggregation: view.LastValue(),
		}); err != nil {
		panic(err)
	}

}

func registerMetrics(tags []tag.Key, m ...stats.Measure) {
	for idx := range m {
		err := view.Register(&view.View{
			Name:        m[idx].Name(),
			Description: m[idx].Description(),
			TagKeys:     tags,
			Measure:     m[idx],
			Aggregation: view.Count(),
		})
		if err != nil {
			panic(err)
		}
	}
}
