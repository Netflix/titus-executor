package ec2wrapper

import (
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

func init() {
	registerMetrics([]tag.Key{keyInterface}, invalidateInterfaceFromCache, storedInterfaceInCache, getInterfaceFromCache, getInterfaceFromCacheSuccess, getInterfaceMs, getInterfaceCount, getInterfaceSuccess)
	registerMetrics([]tag.Key{keyInstance}, invalidateInstanceFromCache, storedInstanceInCache, getInstanceFromCache, getInstanceFromCacheSuccess, getInstanceMs, getInstanceCount, getInstanceSuccess)
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
