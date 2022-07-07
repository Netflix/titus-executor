package db

import (
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
)

var (
	// Distribution measures
	getLeastUsedSubnetByAccountLatency        = stats.Int64("db.query.getLeastUsedSubnetByAccount.latency", "The DB query latency to get the least used subnet by account", stats.UnitMilliseconds)
	getLeastUsedSubnetBySubnetIDsLatency      = stats.Int64("db.query.getLeastUsedSubnetBySubnetIDs.latency", "The DB query latency to get the least used subnet by subnet ids", stats.UnitMilliseconds)
	getAndLockAssignmentByTaskIDLatency       = stats.Int64("db.query.getAndLockAssignmentByTaskID.latency", "The DB query latency to get and lock an assignment by task id", stats.UnitMilliseconds)
	getAndLockAssignmentByAssignmentIDLatency = stats.Int64("db.query.getAndLockAssignmentByAssignmentID.latency", "The DB query latency to get and lock an assignment by id", stats.UnitMilliseconds)
)

func init() {
	distributionMeasures := []stats.Measure{
		getLeastUsedSubnetByAccountLatency,
		getLeastUsedSubnetBySubnetIDsLatency,
		getAndLockAssignmentByTaskIDLatency,
		getAndLockAssignmentByAssignmentIDLatency,
	}
	for _, measure := range distributionMeasures {
		if err := view.Register(
			&view.View{
				Name:        measure.Name(),
				Description: measure.Description(),
				Measure:     measure,
				Aggregation: view.Count(),
			},
		); err != nil {
			panic(err)
		}
	}
}
