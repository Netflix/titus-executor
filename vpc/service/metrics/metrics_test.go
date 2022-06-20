package metrics

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/vpc/service/db"
	db_test "github.com/Netflix/titus-executor/vpc/service/db/test"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"go.opencensus.io/stats/view"
)

// A metrics exporter for test that simply saves metrics in memory.
type TestMetricsExporter struct {
	sync.Mutex
	values         map[string]float64
	previousValues map[string]float64
}

func NewTestMetricsExporter() *TestMetricsExporter {
	return &TestMetricsExporter{values: map[string]float64{}, previousValues: make(map[string]float64)}
}

func (e *TestMetricsExporter) ExportView(vd *view.Data) {
	e.Lock()
	defer e.Unlock()
	for _, row := range vd.Rows {
		tags := make(map[string]string, len(row.Tags))
		for idx := range row.Tags {
			tags[row.Tags[idx].Key.Name()] = row.Tags[idx].Value
		}

		key := vd.View.Name
		switch v := row.Data.(type) {
		case *view.DistributionData:
			// TODO: Support
			break
		case *view.CountData:
			if prevValue, ok := e.previousValues[key]; ok {
				e.values[key] += float64(v.Value) - prevValue
			} else {
				e.values[key] += float64(v.Value)
			}
			e.previousValues[key] = float64(v.Value)
		case *view.SumData:
			e.values[key] += v.Value
		case *view.LastValueData:
			e.values[key] = v.Value
		}
	}
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func skipIfNoDocker(t *testing.T) {
	c, err := net.Dial("unix", "/var/run/docker.sock")
	if err != nil {
		t.Skip("Skip because no docker daemon is running")
	}
	defer c.Close()
}

func TestCollectTableMetrics(t *testing.T) {
	skipIfNoDocker(t)
	ctx := context.Background()
	c, err := db_test.StartPostgresContainer(ctx)
	if err != nil {
		t.Fatalf("failed to start postgress container: %s", err)
	}
	defer func() {
		err = c.Shutdown(ctx)
		if err != nil {
			t.Fatalf("failed to clean up container: %s", err)
		}
	}()
	testDb, err := c.Connect(ctx)
	if err != nil {
		t.Fatalf("failed to connect to test DB: %s", err)
	}
	defer testDb.Close()
	// Set up tables
	err = db.MigrateTo(ctx, testDb, 40, false)
	if err != nil {
		t.Fatalf("failed to set up tables: %s", err)
	}

	numSubnets := rand.Intn(100) + 1     // nolint: gosec
	numAssignments := rand.Intn(100) + 1 // nolint: gosec
	numBranchEnis := rand.Intn(100) + 1  // nolint: gosec
	// Number of ENIs that has an "attached" row in branch_eni_attachments table
	numAttachedBranchEnis := rand.Intn(numBranchEnis) // nolint: gosec
	// Number of ENIs that has an "unattached" row in branch_eni_attachments table
	numUnattachedBranchEnis := rand.Intn(numBranchEnis - numAttachedBranchEnis) // nolint: gosec
	// The rest of the ENIs don't have a row in branch_eni_attachments table at all
	numBranchEniAttachments := numAttachedBranchEnis + numUnattachedBranchEnis

	// Insert some dummy data
	{
		err = db_test.InsertSubnets(testDb, numSubnets)
		if err != nil {
			t.Fatalf("failed to insert dummy subnets: %s", err)
		}
		err = db_test.InsertBranchEnis(testDb, numBranchEnis)
		if err != nil {
			t.Fatalf("failed to insert dummy branch enis: %s", err)
		}
		err = db_test.InsertBranchEniAttachments(testDb, 0, numAttachedBranchEnis, "attached")
		if err != nil {
			t.Fatalf("failed to insert dummy branch eni attachments: %s", err)
		}
		err = db_test.InsertBranchEniAttachments(testDb, numAttachedBranchEnis, numBranchEniAttachments, "unattached")
		if err != nil {
			t.Fatalf("failed to insert dummy branch eni attachments: %s", err)
		}
		err = db_test.InsertAssignments(testDb, numAssignments)
		if err != nil {
			t.Fatalf("failed to insert dummy assignments: %s", err)
		}
	}

	exporter := NewTestMetricsExporter()

	view.SetReportingPeriod(time.Second)
	view.RegisterExporter(exporter)

	collectorCtx, cancelFunc := context.WithCancel(ctx)
	// Collect
	collector := NewCollector(collectorCtx, testDb, &CollectorConfig{TableMetricsInterval: time.Second})
	collector.Start()

	// Both the collect and reporting intervals are 1 second.
	// After at most 3 seconds, the metrics should have been exported.
	time.Sleep(time.Second * 3)
	cancelFunc()

	// Verify that the counters are correctly exported
	{
		exporter.Lock()
		defer exporter.Unlock()

		assert.Equal(t, float64(numSubnets), exporter.values["subnets.count"])
		assert.Equal(t, float64(numBranchEnis), exporter.values["branch_enis.count"])
		assert.Equal(t, float64(numBranchEniAttachments), exporter.values["branch_eni_attachments.count"])
		assert.Equal(t, float64(numBranchEnis-numAttachedBranchEnis), exporter.values["unattached_enis.count"])
		assert.Equal(t, float64(numAssignments), exporter.values["assignments.count"])
	}
}
