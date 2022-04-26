package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"

	"contrib.go.opencensus.io/exporter/zipkin"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/db/wrapper"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	ccache "github.com/karlseguin/ccache/v2"
	"github.com/lib/pq"
	openzipkin "github.com/openzipkin/zipkin-go"
	"github.com/openzipkin/zipkin-go/model"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"k8s.io/apimachinery/pkg/util/sets"
)

var enableIntegrationTests, record bool
var dbURL string
var integrationTestTimeout time.Duration
var testAZ, testAccount, testSecurityGroupID, wd, subnets, workerRole, testResetSg string

const (
	Unattached  = "unattached"
	Unattaching = "unattaching"
)

func TestMain(m *testing.M) {
	wrapper.LogTransactions = true
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

	flag.BoolVar(&enableIntegrationTests, "enable-integration-tests", false, "Enable running integration tests")
	flag.StringVar(&dbURL, "db-url", "", "Database URL")
	flag.DurationVar(&integrationTestTimeout, "integration-test-timeout", 5*time.Minute, "The maximum amount of time a single integration test can take")
	flag.StringVar(&testAZ, "az", "", "The AZ to us for the test")
	flag.StringVar(&testAccount, "account", "", "The account ID to use for the test")
	flag.StringVar(&testSecurityGroupID, "security-group", "", "The security group id to use for testing")
	flag.BoolVar(&record, "record", true, "Record span for each test")
	flag.StringVar(&subnets, "subnets", "", "Subnets for stress testing")
	flag.StringVar(&workerRole, "worker-role", "", "The role to use for the AWS IAM worker")
	flag.StringVar(&testResetSg, "reset-security-group", "sg-01d281a4cc5f620c9", "Security group unattached to any container")
	var err error
	wd, err = os.Getwd()
	if err != nil {
		panic(err)
	}
	flag.Parse()
	os.Exit(m.Run())
}

type integrationTestMetadata struct {
	region                 string
	account                string
	az                     string
	vpc                    string
	subnetID               string
	subnetIDs              []string
	defaultSecurityGroupID string
	testSecurityGroupID    string
	testResetSg            string
}

func newTestServiceInstance(t *testing.T) *vpcService {
	t.Logf("DB URL is  %s", dbURL)
	connector, err := pq.NewConnector(dbURL)
	assert.NilError(t, err)
	hostname, err := os.Hostname()
	assert.NilError(t, err)
	wrappedConnector := wrapper.NewConnectorWrapper(connector, wrapper.ConnectorWrapperConfig{
		MaxConcurrentSerialTransactions: 10,
		Hostname:                        hostname,
	})
	db := sql.OpenDB(wrappedConnector)
	assert.NilError(t, db.Ping())
	return &vpcService{
		db:       db,
		dbURL:    dbURL,
		hostname: hostname,
		ec2:      ec2wrapper.NewEC2SessionManager(workerRole),

		branchNetworkInterfaceDescription: vpc.DefaultBranchNetworkInterfaceDescription,
		trunkNetworkInterfaceDescription:  vpc.DefaultTrunkNetworkInterfaceDescription,
		subnetCIDRReservationDescription:  vpc.DefaultSubnetCIDRReservationDescription,

		trunkTracker:              newTrunkTrackerCache(),
		invalidSecurityGroupCache: ccache.New(ccache.Configure()),
		subnetCacheExpirationTime: time.Second * 10,
	}
}

func TestIntegrationTests(t *testing.T) {
	t.Logf("Integration tests: %t", enableIntegrationTests)
	if !enableIntegrationTests {
		t.Skip("Integration tests are not enabled")
	}
	runIntegrationTest(t, "trunkENITests", trunkENITests)
	runIntegrationTest(t, "branchENITests", branchENITests)
	runIntegrationTest(t, "testAssociate", testAssociate)
	runIntegrationTest(t, "testGenerateAssignmentID", testGenerateAssignmentID)
	runIntegrationTest(t, "testGenerateAssignmentIDWithFault", testGenerateAssignmentIDWithFault)
	runIntegrationTest(t, "testGenerateAssignmentIDStressTest", testGenerateAssignmentIDStressTest)
	runIntegrationTest(t, "testGenerateAssignmentIDBranchENIsStress", testGenerateAssignmentIDBranchENIsStress)
	runIntegrationTest(t, "testActionWorker", testActionWorker)
	runIntegrationTest(t, "testGenerateAssignmentIDNewSG", testGenerateAssignmentIDNewSG)
	runIntegrationTest(t, "testGenerateAssignmentIDWithTransitionNS", testGenerateAssignmentIDWithTransitionNS)
	runIntegrationTest(t, "testGenerateAssignmentIDWithAddress", testGenerateAssignmentIDWithAddress)
	runIntegrationTest(t, "testResetSecurityGroup", testResetSecurityGroup)
	runIntegrationTest(t, "testAllocateAndDeallocateStaticAddress", testAllocateAndDeallocateStaticAddress)
}

type zipkinReporter struct {
	f       *os.File
	encoder *json.Encoder
	lock    sync.Mutex
}

func (zr *zipkinReporter) Close() error {
	return zr.f.Close()
}

func (zr *zipkinReporter) Send(m model.SpanModel) {
	zr.lock.Lock()
	defer zr.lock.Unlock()
	_ = zr.encoder.Encode(m)
}

type integrationTestFunc func(context.Context, *testing.T, integrationTestMetadata, *vpcService, *ec2wrapper.EC2Session)

func runIntegrationTest(tParent *testing.T, testName string, testFunction integrationTestFunc) {
	tParent.Run(testName, func(t *testing.T) {
		if record {
			endpoint, err := openzipkin.NewEndpoint("titus-vpc-service", "")
			assert.NilError(t, err)
			assert.Assert(t, endpoint != nil)

			spanFileName := filepath.Join(wd, fmt.Sprintf("trace-%s.log", testName))
			t.Logf("Setting up span recording to %s", spanFileName)
			file, err := os.OpenFile(spanFileName, os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
			assert.NilError(t, err)
			encoder := json.NewEncoder(file)

			/*
				reporter := recorder.NewReporter()

				defer func() {
					spans := reporter.Flush()
					for idx := range spans {
						assert.NilError(t, encoder.Encode(spans[idx]))
					}
					assert.NilError(t, file.Close())
				}()

			*/
			reporter := &zipkinReporter{
				f:       file,
				encoder: encoder,
			}
			defer func() {
				assert.NilError(t, reporter.Close())
			}()
			localEndpoint, err := openzipkin.NewEndpoint("titus-vpc-service", "")
			assert.NilError(t, err)
			ze := zipkin.NewExporter(reporter, localEndpoint)
			trace.RegisterExporter(ze)
			defer trace.UnregisterExporter(ze)
		}
		ctx, cancel := context.WithTimeout(context.Background(), integrationTestTimeout)
		defer cancel()
		logrusLogger := logrus.StandardLogger()
		logrusLogger.SetLevel(logrus.DebugLevel)
		ctx = logger.WithLogger(ctx, logrusLogger)
		ctx = logger.WithField(ctx, "test", testName)

		// TODO: Zipkin?
		svc := newTestServiceInstance(t)
		md := integrationTestMetadata{
			az:                  testAZ,
			account:             testAccount,
			testSecurityGroupID: testSecurityGroupID,
			testResetSg:         testResetSg,
		}

		row := svc.db.QueryRowContext(ctx, "SELECT region FROM availability_zones WHERE zone_name = $1 AND account_id = $2 LIMIT 1", testAZ, testAccount)
		assert.NilError(t, row.Scan(&md.region))

		row = svc.db.QueryRowContext(ctx, "SELECT vpc_id, subnet_id FROM subnets WHERE az = $1 AND account_id = $2 LIMIT 1", testAZ, testAccount)
		assert.NilError(t, row.Scan(&md.vpc, &md.subnetID))

		if subnets != "" {
			md.subnetIDs = strings.Split(subnets, ",")
		}

		session, err := svc.ec2.GetSessionFromAccountAndRegion(ctx, ec2wrapper.Key{Region: md.region, AccountID: md.account})
		assert.NilError(t, err)

		securityGroupIDs, err := session.GetDefaultSecurityGroups(ctx, md.vpc)
		assert.NilError(t, err)

		md.defaultSecurityGroupID = aws.StringValueSlice(securityGroupIDs)[0]

		testFunction(ctx, t, md, svc, session)
	})
}

func trunkENITests(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	// 1. Kick out the trunk ENI lock
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))

	// Create dangling ENIs
	eni, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	logger.G(ctx).WithField("eni", eni.String()).Debug("Created test trunk ENI")

	var id int
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM trunk_enis WHERE trunk_eni = 'eni-055a2f17c777132a3'")
		assert.NilError(t, err)
		row := tx.QueryRowContext(ctx, `
INSERT INTO trunk_enis(trunk_eni, account_id, az, subnet_id, vpc_id, region) VALUES ('eni-055a2f17c777132a3', $1, $2, $3, $4, $5)
RETURNING id
`, md.account, md.az, md.subnetID, md.vpc, md.region)
		assert.NilError(t, row.Scan(&id))
		return nil
	}))

	orphanedTrunkENIs, err := service.getDatabaseOrphanedTrunkENIs(ctx, item, sets.NewString())
	assert.NilError(t, err)
	assert.Assert(t, orphanedTrunkENIs.Has("eni-055a2f17c777132a3"))

	var count int
	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM trunk_enis WHERE id = $1", id)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, count == 1)
	assert.NilError(t, service.reconcileTrunkENIsForRegionAccount(ctx, item))
	row = service.db.QueryRowContext(ctx, "SELECT count(*) FROM trunk_enis WHERE id = $1", id)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, count == 0)

	_, err = session.DescribeNetworkInterfaces(ctx, ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{eni.NetworkInterfaceId},
	})
	assert.Assert(t, err != nil)
	awsErr := ec2wrapper.RetrieveEC2Error(err)
	assert.Assert(t, awsErr != nil)
	assert.Assert(t, awsErr.Code() == ec2wrapper.InvalidNetworkInterfaceIDNotFound)
}

func branchENITests(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	assert.Assert(t, md.testSecurityGroupID != "")
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}

	subnet := &subnet{
		az:        md.az,
		vpcID:     md.vpc,
		accountID: md.account,
		subnetID:  md.subnetID,
		cidr:      "", // This isn't needed for what we're doing
		region:    md.region,
	}

	group, groupCtx := errgroup.WithContext(ctx)

	reconcileBranchENIsTask := service.reconcileBranchENIsLongLivedTask()
	group.Go(func() error {
		return service.preemptLock(groupCtx, item, reconcileBranchENIsTask)
	})
	deleteExcessBranchesTask := service.deleteExcessBranchesLongLivedTask()
	group.Go(func() error {
		return service.preemptLock(groupCtx, subnet, deleteExcessBranchesTask)
	})

	assert.NilError(t, group.Wait())

	dangling, err := session.CreateNetworkInterface(ctx, ec2.CreateNetworkInterfaceInput{
		Description: aws.String(vpc.DefaultBranchNetworkInterfaceDescription),
		SubnetId:    aws.String(md.subnetID),
	})
	assert.NilError(t, err)
	logger.G(ctx).WithField("eni", aws.StringValue(dangling.NetworkInterface.NetworkInterfaceId)).Debug("Created test dangling branch ENI")

	var differentSGInDB, nonExistentSGs *ec2.NetworkInterface

	var id int
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM branch_enis WHERE branch_eni = 'eni-055a2f17c777132a4'")
		assert.NilError(t, err)
		row := tx.QueryRowContext(ctx, `
INSERT INTO branch_enis(branch_eni, account_id, subnet_id, az, vpc_id) VALUES ('eni-055a2f17c777132a4', $1, $2, $3, $4)
RETURNING id
`, md.account, md.subnetID, md.az, md.vpc)
		assert.NilError(t, row.Scan(&id))

		differentSGInDB, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		assert.NilError(t, err)
		_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1 WHERE branch_eni = $2",
			pq.Array([]string{md.testSecurityGroupID}), aws.StringValue(differentSGInDB.NetworkInterfaceId))
		logger.G(ctx).WithField("eni", aws.StringValue(differentSGInDB.NetworkInterfaceId)).Debug("Created test ENI with test SG in DB")
		assert.NilError(t, err)

		// Although we modify the security groups in assign private IP before we write back to the database,
		// there can be a race condition where someone fixes the interfaces in AWS, but doesn't fix them
		// in the database
		nonExistentSGs, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		assert.NilError(t, err)
		_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = $1 WHERE branch_eni = $2",
			pq.Array([]string{"sg-f0000000"}), aws.StringValue(nonExistentSGs.NetworkInterfaceId))
		logger.G(ctx).WithField("eni", aws.StringValue(nonExistentSGs.NetworkInterfaceId)).Debug("Created test ENI with non-existent SG in DB")
		assert.NilError(t, err)

		return nil
	}))

	assert.NilError(t, service.reconcileBranchENIsForRegionAccount(ctx, item))

	var count int

	// Make sure dangling ENIs are deleted.
	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_enis WHERE branch_eni = $1", aws.StringValue(dangling.NetworkInterface.NetworkInterfaceId))
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 0))
	_, err = session.DescribeNetworkInterfaces(ctx, ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{dangling.NetworkInterface.NetworkInterfaceId},
	})
	assert.ErrorContains(t, err, "InvalidNetworkInterfaceID.NotFound")

	row = service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_enis WHERE id = $1", id)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 0))

	var dirtySecurityGroups bool
	row = service.db.QueryRowContext(ctx, "SELECT dirty_security_groups FROM branch_enis WHERE branch_eni = $1", aws.StringValue(nonExistentSGs.NetworkInterfaceId))
	assert.NilError(t, row.Scan(&dirtySecurityGroups))
	assert.Assert(t, dirtySecurityGroups)

	row = service.db.QueryRowContext(ctx, "SELECT dirty_security_groups FROM branch_enis WHERE branch_eni = $1", aws.StringValue(differentSGInDB.NetworkInterfaceId))
	assert.NilError(t, row.Scan(&dirtySecurityGroups))
	assert.Assert(t, dirtySecurityGroups)
}

// The first group is for the preemption, the second group is for the workers
func startAssociationAndDisassociationWorkers(ctx context.Context, t *testing.T, service *vpcService) (*errgroup.Group, *errgroup.Group) {
	associateWorker := service.associateActionWorker()
	disassociateWorker := service.disassociateActionWorker()
	nilItems, _ := nilItemEnumerator(ctx)
	assert.Assert(t, is.Len(nilItems, 1))

	workerGroup, workerCtx := errgroup.WithContext(ctx)
	preemptionGroup, preemptionCtx := errgroup.WithContext(ctx)
	preemptionGroup.Go(func() error {
		if err := service.preemptLock(preemptionCtx, nilItems[0], associateWorker.longLivedTask()); err != nil {
			return err
		}
		workerGroup.Go(func() error {
			ctx2 := logger.WithField(workerCtx, "worker", "associateWorker")
			return associateWorker.loop(ctx2, nilItems[0])
		})
		return nil
	})
	preemptionGroup.Go(func() error {
		if err := service.preemptLock(preemptionCtx, nilItems[0], disassociateWorker.longLivedTask()); err != nil {
			return err
		}
		workerGroup.Go(func() error {
			ctx2 := logger.WithField(workerCtx, "worker", "disassociateWorker")
			return disassociateWorker.loop(ctx2, nilItems[0])
		})
		return nil
	})

	return preemptionGroup, workerGroup
}

func testAssociate(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	ctx, span := trace.StartSpan(ctx, "testAssociate")
	defer span.End()

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	var branchENI *ec2.NetworkInterface
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		branchENI, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		return err
	}))

	assoc, err := service.doAssociateTrunkNetworkInterface(ctx, aws.StringValue(trunkENI.NetworkInterfaceId), aws.StringValue(branchENI.NetworkInterfaceId), 5)
	assert.NilError(t, err)

	logger.G(ctx).WithField("associationID", assoc.AssociationId).Debug("Completed association")
	// Now disassociate
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "SELECT branch_eni FROM branch_enis WHERE branch_eni = $1", aws.StringValue(branchENI.NetworkInterfaceId))
		assert.NilError(t, err)
		_, err = tx.ExecContext(ctx, "SELECT branch_eni FROM branch_eni_attachments WHERE branch_eni = $1", aws.StringValue(branchENI.NetworkInterfaceId))
		assert.NilError(t, err)
		assert.NilError(t, service.disassociateNetworkInterface(ctx, tx, session, assoc.AssociationId, false))
		return nil
	}))
	logger.G(ctx).WithField("associationID", assoc.AssociationId).Debug("Completed disassociation")

	_, err = session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice([]string{assoc.AssociationId}),
	})
	assert.Assert(t, err != nil)
	awsErr := ec2wrapper.RetrieveEC2Error(err)
	assert.Assert(t, is.Equal(awsErr.Code(), ec2wrapper.InvalidAssociationIDNotFound))

	var state string
	row := service.db.QueryRowContext(ctx, "SELECT state FROM branch_eni_attachments WHERE association_id = $1", assoc.AssociationId)
	assert.NilError(t, row.Scan(&state))
	assert.Assert(t, is.Equal(state, "unattached"))
}

func withTransaction(ctx context.Context, db *sql.DB, txFN func(context.Context, *sql.Tx) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		err = errors.Wrap(err, "Could not start database transaction")
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	// Handle panics
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	err = txFN(ctx, tx)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = errors.Wrap(err, "Could not commit transaction")
		return err
	}
	return err
}

func testGenerateAssignmentIDBranchENIsStress(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	if testing.Short() {
		t.Skip("Stress test not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*2)
	defer cancel()
	if len(md.subnetIDs) == 0 {
		t.Skip("No subnet IDs provided for stress testing")
	}
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}

	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	g1, g2 := startAssociationAndDisassociationWorkers(workerCtx, t, service)

	assert.NilError(t, g1.Wait())
	subnet, err := service.getSubnet(ctx, md.az, md.account, md.subnetIDs)
	assert.NilError(t, err)

	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_enis WHERE subnet_id = $1 AND branch_eni NOT IN (SELECT branch_eni FROM branch_eni_attachments WHERE state = 'attached')", subnet.subnetID)
	var count int
	assert.NilError(t, row.Scan(&count))
	t.Logf("Initial number of free ENIs in subnet %s is %d", subnet.subnetID, count)

	req := getENIRequest{
		region:           md.region,
		branchENIAccount: md.account,
		subnet:           subnet,
		securityGroups:   []string{md.defaultSecurityGroupID},
		maxIPAddresses:   1,
		maxBranchENIs:    14,
	}
	const numberOfBranchesToGenerate = 120
	trunks := make([]*ec2.NetworkInterface, (numberOfBranchesToGenerate/req.maxBranchENIs)+1)
	for idx := range trunks {
		trunkENI, err := service.createNewTrunkENI(ctx, session, &subnet.subnetID, 3)
		assert.NilError(t, err)
		defer func() {
			assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
		}()

		logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")
		trunks[idx] = trunkENI
	}

	var success int64

	group := &multierror.Group{}
	trunkENIIDs := make([]string, len(trunks))
	for idx := range trunks {
		trunkENI := trunks[idx]
		trunkENIIDs[idx] = aws.StringValue(trunkENI.NetworkInterfaceId)
		for i := 0; i < req.maxBranchENIs; i++ {
			myGetENIRequest := req
			myGetENIRequest.assignmentID = fmt.Sprintf("testGenerateAssignmentIDBranchENIsStress-%d-%s", i, uuid.New().String())
			myGetENIRequest.trunkENI = aws.StringValue(trunkENI.NetworkInterfaceId)
			myGetENIRequest.subnet = subnet
			myGetENIRequest.trunkENIAccount = aws.StringValue(trunkENI.OwnerId)
			group.Go(func() error {
				_, err2 := service.generateAssignmentID(ctx, myGetENIRequest)
				if err2 == nil {
					atomic.AddInt64(&success, 1)
				}
				return err2
			})
		}
	}

	mErr := group.Wait()
	t.Logf("Success: %d", atomic.LoadInt64(&success))

	assert.NilError(t, mErr.ErrorOrNil())

	associationIDs := []string{}
	rows, err := service.db.QueryContext(ctx, "SELECT association_id FROM branch_eni_attachments WHERE trunk_eni = any($1) AND state = 'attached'", pq.Array(trunkENIIDs))
	assert.NilError(t, err)
	for rows.Next() {
		var associationID string
		assert.NilError(t, rows.Scan(&associationID))
		associationIDs = append(associationIDs, associationID)
	}

	assert.Assert(t, is.Equal(len(trunks)*req.maxBranchENIs, len(associationIDs)))
	_, err = session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice(associationIDs),
	})
	assert.NilError(t, err)
	workerCancel()
	assert.Error(t, g2.Wait(), context.Canceled.Error())
}

func testGenerateAssignmentIDStressTest(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	if testing.Short() {
		t.Skip("Stress test not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if len(md.subnetIDs) == 0 {
		t.Skip("No subnet IDs provided for stress testing")
	}
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	g1, g2 := startAssociationAndDisassociationWorkers(workerCtx, t, service)

	trunkENIs := make([]*ec2.NetworkInterface, len(md.subnetIDs))
	subnets := make([]*subnet, len(md.subnetIDs))
	for idx := range trunkENIs {
		trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetIDs[idx], 3)
		assert.NilError(t, err)
		defer func() {
			assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
		}()
		trunkENIs[idx] = trunkENI
		subnets[idx], err = service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
		assert.NilError(t, err)
	}

	assert.NilError(t, g1.Wait())

	const (
		addressesPerTrunk = 50
		maxIPAddresses    = 25
		maxBranchENIs     = 120
	)

	wg := &sync.WaitGroup{}
	assignments := make([]*assignment, addressesPerTrunk*len(trunkENIs))
	wg.Add(len(assignments))
	group := multierror.Group{}
	n := 0
	for idx := range trunkENIs {
		eni := trunkENIs[idx]
		for i := 0; i < addressesPerTrunk; i++ {
			assignmentIndex := n
			n++
			req := getENIRequest{
				assignmentID:     fmt.Sprintf("testGenerateAssignmentIDStressTest-%s-%d", aws.StringValue(eni.NetworkInterfaceId), n),
				region:           md.region,
				trunkENI:         aws.StringValue(eni.NetworkInterfaceId),
				trunkENIAccount:  aws.StringValue(eni.OwnerId),
				branchENIAccount: md.account,
				subnet:           subnets[idx],
				securityGroups:   []string{md.defaultSecurityGroupID, md.testSecurityGroupID},
				maxIPAddresses:   maxIPAddresses,
				maxBranchENIs:    maxBranchENIs,
			}

			group.Go(func() error {
				wg.Done()
				wg.Wait()
				ass, err := service.generateAssignmentID(ctx, req)
				assignments[assignmentIndex] = ass
				return err
			})
		}
	}

	t.Logf("%d workers started", n)

	assert.NilError(t, group.Wait().ErrorOrNil())

	branchENIs := sets.NewString()
	for idx := range assignments {
		branchENIs.Insert(assignments[idx].branch.id)
	}
	t.Logf("branch ENIs: %v", branchENIs.List())
	t.Log(assignments)

	workerCancel()
	assert.Error(t, g2.Wait(), context.Canceled.Error())
}

func testGenerateAssignmentIDWithFault(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	g1, g2 := startAssociationAndDisassociationWorkers(workerCtx, t, service)
	assert.NilError(t, g1.Wait())

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	defer func() {
		assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
	}()

	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	subnet, err := service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
	assert.NilError(t, err)

	req := getENIRequest{
		assignmentID:     fmt.Sprintf("testGenerateAssignmentIDWithFault-%s", uuid.New().String()),
		region:           md.region,
		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		branchENIAccount: md.account,
		subnet:           subnet,
		securityGroups:   []string{md.defaultSecurityGroupID},
		maxIPAddresses:   50,
		maxBranchENIs:    2,
	}

	fakeErr := errors.New("fault error")
	ctx = registerFault(ctx, afterAttachFaultKey, func(ctx context.Context, opts ...interface{}) error {
		return fakeErr
	})

	_, err = service.generateAssignmentID(ctx, req)
	assert.Assert(t, is.ErrorContains(err, "fault error"))
	// Check that the worker picked this up
	// it might need a second
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var id int
	var state string
	var associationID sql.NullString
	for {
		select {
		case <-ticker.C:
			logger.G(ctx).Debug("Checking ENI state")
			// Check if things are attached
			row := service.db.QueryRowContext(ctx, "SELECT id, state, association_id FROM branch_eni_attachments WHERE trunk_eni = $1", aws.StringValue(trunkENI.NetworkInterfaceId))
			assert.NilError(t, row.Scan(&id, &state, &associationID))
			if state == "attached" {
				goto out
			}
		case <-ctx.Done():
			assert.NilError(t, ctx.Err())
		}
	}
out:
	assert.Assert(t, associationID.Valid)
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err = service.startDissociation(ctx, tx, associationID.String, false)
		return err
	}))

	row := service.db.QueryRowContext(ctx, "SELECT state FROM branch_eni_attachments WHERE id = $1", id)
	assert.NilError(t, row.Scan(&state))
	assert.Assert(t, state == Unattaching || state == Unattached)

	// Maybe make this smarter than a second
	time.Sleep(time.Second)
	row = service.db.QueryRowContext(ctx, "SELECT state FROM branch_eni_attachments WHERE id = $1", id)
	assert.NilError(t, row.Scan(&state))
	assert.Assert(t, state == Unattached)

	workerCancel()
	assert.Error(t, g2.Wait(), context.Canceled.Error())
}

func testGenerateAssignmentIDNewSG(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}

	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	defer func() {
		assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
	}()

	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	subnet, err := service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
	assert.NilError(t, err)

	var securityGroupID string
	var id int
	row := service.db.QueryRowContext(ctx, "SELECT id, group_id FROM security_groups WHERE group_name = 'titusvpcservice--unittest'")
	assert.NilError(t, row.Scan(&id, &securityGroupID))

	req := getENIRequest{
		region:           md.region,
		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		branchENIAccount: md.account,
		subnet:           subnet,
		securityGroups:   []string{"sg-f00"},
		maxIPAddresses:   50,
		maxBranchENIs:    2,
		assignmentID:     fmt.Sprintf("testGenerateAssignmentID-%s-%s", t.Name(), uuid.New().String()),
	}
	_, err = service.generateAssignmentID(ctx, req)
	assert.ErrorContains(t, err, "Could not find security group sg-f00")

	_, err = service.generateAssignmentID(ctx, req)
	assert.ErrorContains(t, err, "Could not find security group sg-f00; next lookup will be attempted")
	service.invalidSecurityGroupCache.Delete("sg-f00")

	_, err = service.generateAssignmentID(ctx, req)
	assert.ErrorContains(t, err, "Could not find security group sg-f00")

	// Let's make sure security groups can be populated at runtime correctly.
	_, err = service.db.ExecContext(ctx, "DELETE FROM security_groups WHERE id = $1", id)
	assert.NilError(t, err)

	req.securityGroups = []string{securityGroupID}
	_, err = service.generateAssignmentID(ctx, req)
	assert.NilError(t, err)
}

func testResetSecurityGroup(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	defer func() {
		assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
	}()

	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	subnet, err := service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
	assert.NilError(t, err)

	req := getENIRequest{
		region: md.region,

		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		branchENIAccount: md.account,
		subnet:           subnet,
		securityGroups:   []string{md.defaultSecurityGroupID, md.testResetSg},
		maxIPAddresses:   1,
		maxBranchENIs:    1,
	}

	wg := &sync.WaitGroup{}
	wg.Add(req.maxIPAddresses)
	group := &multierror.Group{}
	assignmentIDs := make([]*assignment, req.maxIPAddresses)
	for i := 0; i < req.maxIPAddresses; i++ {
		myGetENIRequest := req
		idx := i
		myGetENIRequest.assignmentID = fmt.Sprintf("testGenerateAssignmentID-%d-%s", i, uuid.New().String())
		group.Go(func() error {
			wg.Done()
			wg.Wait()
			response, err := service.generateAssignmentID(ctx, myGetENIRequest)
			assignmentIDs[idx] = response
			return err
		})
	}

	mErr := group.Wait()
	assert.NilError(t, mErr.ErrorOrNil())

	time.Sleep(time.Second * 3)
	var id int
	var state string
	var associationID sql.NullString
	// Verify we only attached one branch ENI
	row := service.db.QueryRowContext(ctx, "SELECT id, state, association_id FROM branch_eni_attachments WHERE trunk_eni = $1 AND state = 'attached'", aws.StringValue(trunkENI.NetworkInterfaceId))
	assert.NilError(t, row.Scan(&id, &state, &associationID))
	assert.Assert(t, associationID.Valid)

	logger.G(ctx).Debug("Attachment verified..Going to reset the SG - should fail", md.testResetSg)
	//Now that the ENI is createdm reset the SG - should fail
	_, err = service.ResetSecurityGroup(ctx, &titus.ResetSecurityGroupRequest{SecurityGroupID: md.testResetSg})
	assert.Check(t, err != nil)
	if e, ok := status.FromError(err); ok {
		assert.Equal(t, e.Code(), codes.FailedPrecondition)
	}

	logger.G(ctx).Debug(" going to delete assignment ", assignmentIDs[0].assignmentID)
	_, err = service.db.ExecContext(ctx, "DELETE FROM assignments WHERE id = $1", assignmentIDs[0].assignmentID)
	assert.NilError(t, err)

	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err = service.startDissociation(ctx, tx, associationID.String, true)
		return err
	}))

	// Maybe make this smarter than a second
	time.Sleep(time.Second)
	row = service.db.QueryRowContext(ctx, "SELECT state FROM branch_eni_attachments WHERE id = $1", id)
	assert.NilError(t, row.Scan(&state))
	assert.Assert(t, state == "unattached")
	logger.G(ctx).Debug("Dissociate complete, for ", id, " call reset again ..", md.testResetSg)

	time.Sleep(time.Second * 1)
	_, err = service.ResetSecurityGroup(ctx, &titus.ResetSecurityGroupRequest{SecurityGroupID: md.testResetSg})
	assert.NilError(t, err)
}

func testGenerateAssignmentID(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	defer func() {
		assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
	}()

	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	subnet, err := service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
	assert.NilError(t, err)

	req := getENIRequest{
		region: md.region,

		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		branchENIAccount: md.account,
		subnet:           subnet,
		securityGroups:   []string{md.defaultSecurityGroupID},
		maxIPAddresses:   50,
		maxBranchENIs:    2,
	}

	wg := &sync.WaitGroup{}
	wg.Add(req.maxIPAddresses)
	group := &multierror.Group{}
	assignmentIDs := make([]*assignment, req.maxIPAddresses)
	for i := 0; i < req.maxIPAddresses; i++ {
		myGetENIRequest := req
		idx := i
		myGetENIRequest.assignmentID = fmt.Sprintf("testGenerateAssignmentID-%d-%s", i, uuid.New().String())
		group.Go(func() error {
			wg.Done()
			wg.Wait()
			response, err := service.generateAssignmentID(ctx, myGetENIRequest)
			assignmentIDs[idx] = response
			return err
		})
	}

	mErr := group.Wait()
	assert.NilError(t, mErr.ErrorOrNil())

	// Verify we only attached one branch ENI
	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_eni_attachments WHERE trunk_eni = $1 AND state = 'attached'", aws.StringValue(trunkENI.NetworkInterfaceId))
	var count int
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 1))

	describeNetworkInterfacesOutput, err := session.DescribeNetworkInterfaces(ctx, ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{&assignmentIDs[0].branch.id},
	})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(describeNetworkInterfacesOutput.NetworkInterfaces, 1))
	assert.Assert(t, is.Len(describeNetworkInterfacesOutput.NetworkInterfaces[0].Groups, 1))
	assert.Assert(t, is.Equal(aws.StringValue(describeNetworkInterfacesOutput.NetworkInterfaces[0].Groups[0].GroupId), md.defaultSecurityGroupID))

	oneExtraAssignmentRequest := req
	oneExtraAssignmentRequest.assignmentID = fmt.Sprintf("testGenerateAssignmentID-%d-%s", 50, uuid.New().String())
	oneExtraAssignmentResponse, err := service.generateAssignmentID(ctx, oneExtraAssignmentRequest)
	assert.NilError(t, err)
	row = service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_eni_attachments WHERE trunk_eni = $1", aws.StringValue(trunkENI.NetworkInterfaceId))
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 2))

	t.Logf("assignmentIDs: %s", assignmentIDs)
	t.Logf("oneExtraAssignmentResponse: %s", oneExtraAssignmentResponse)

	assert.Assert(t, oneExtraAssignmentResponse.branch.id != assignmentIDs[0].branch.id)

	_, err = service.db.ExecContext(ctx, "DELETE FROM assignments WHERE id = $1", oneExtraAssignmentResponse.assignmentID)
	assert.NilError(t, err)

	sgChangeAssignmentRequest := req
	sgChangeAssignmentRequest.securityGroups = []string{md.testSecurityGroupID}
	sgChangeAssignmentRequest.assignmentID = fmt.Sprintf("sgChangeAssignmentRequest-%s", uuid.New().String())
	sgChangeAssignmentResponse, err := service.generateAssignmentID(ctx, sgChangeAssignmentRequest)
	assert.NilError(t, err)

	assert.Assert(t, is.Equal(sgChangeAssignmentResponse.branch.id, oneExtraAssignmentResponse.branch.id))
	describeNetworkInterfacesOutput, err = session.DescribeNetworkInterfaces(ctx, ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{&sgChangeAssignmentResponse.branch.id},
	})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(describeNetworkInterfacesOutput.NetworkInterfaces, 1))
	assert.Assert(t, is.Len(describeNetworkInterfacesOutput.NetworkInterfaces[0].Groups, 1))
	assert.Assert(t, is.Equal(aws.StringValue(describeNetworkInterfacesOutput.NetworkInterfaces[0].Groups[0].GroupId), md.testSecurityGroupID))

	describeTrunkInterfaceAssociationsOutput, err := session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice([]string{sgChangeAssignmentResponse.branch.associationID, assignmentIDs[0].branch.associationID}),
	})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(describeTrunkInterfaceAssociationsOutput.InterfaceAssociations, 2))
	assert.Assert(t, is.Equal(aws.StringValue(describeTrunkInterfaceAssociationsOutput.InterfaceAssociations[0].TrunkInterfaceId), aws.StringValue(trunkENI.NetworkInterfaceId)))
	assert.Assert(t, is.Equal(aws.StringValue(describeTrunkInterfaceAssociationsOutput.InterfaceAssociations[1].TrunkInterfaceId), aws.StringValue(trunkENI.NetworkInterfaceId)))
}

func testActionWorker(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const workedUponSuffix = "-worked-upon"
	doTestWork := func() int {
		_, file, line, ok := runtime.Caller(1)
		filename := filepath.Base(file)
		assert.Assert(t, ok)

		tx, err := service.db.BeginTx(ctx, nil)
		assert.NilError(t, err)
		defer func(t *sql.Tx) {
			_ = t.Rollback()
		}(tx)

		workItem := fmt.Sprintf("%s:%d-%s", filename, line, uuid.New().String())
		row := tx.QueryRowContext(ctx, "INSERT INTO test_work(input) VALUES ($1) RETURNING id", workItem)
		var workItemID int
		assert.NilError(t, row.Scan(&workItemID))

		_, err = tx.ExecContext(ctx, "SELECT pg_notify('test_work_created', $1)", strconv.Itoa(workItemID))
		assert.NilError(t, err)
		assert.NilError(t, tx.Commit())

		return workItemID
	}

	itemCreatedBeforeWorkerStartupWorkitemID := doTestWork()

	group, ctx := errgroup.WithContext(ctx)
	testActionWorker := &actionWorker{
		db:    service.db,
		dbURL: service.dbURL,
		cb: func(ctx context.Context, tx *sql.Tx, id int) (retErr error) {
			ctx, span := trace.StartSpan(ctx, "testActionCallbackSpan")
			defer span.End()
			defer func() {
				tracehelpers.SetStatus(retErr, span)
			}()
			logger.G(ctx).Debug("Starting test action worker callback")
			row := tx.QueryRowContext(ctx, "SELECT input FROM test_work WHERE id = $1", id)
			var input string
			if err := row.Scan(&input); err != nil {
				return err
			}
			output := input + workedUponSuffix
			logger.G(ctx).Debug("Retrieved input")

			if _, err := tx.ExecContext(ctx, "UPDATE test_work SET state = 'done', output = $1 WHERE id = $2", output, id); err != nil {
				return err
			}
			logger.G(ctx).Debug("Updated work to done")

			_, err := tx.ExecContext(ctx, "SELECT pg_notify('test_work_finished', $1)", strconv.Itoa(id))
			logger.G(ctx).WithError(err).Debug("Sent completion notification")
			return err
		},
		creationChannel: "test_work_created",
		finishedChanel:  "test_work_finished",
		name:            "test_worker",
		table:           "test_work",
		maxWorkTime:     time.Minute,
		pendingState:    "undone",

		readyCond: sync.NewCond(&sync.Mutex{}),
	}

	group.Go(func() error {
		err := testActionWorker.loop(ctx, &nilItem{})
		if err != nil {
			logger.G(ctx).WithError(err).Error("test action worker exited")
		}
		return err
	})

	testActionWorker.readyCond.L.Lock()
wait_for_ready:
	if testActionWorker.ready {
		testActionWorker.readyCond.L.Unlock()
	} else {
		testActionWorker.readyCond.Wait()
		goto wait_for_ready
	}

	var listenerPid int
	assert.NilError(t, service.db.QueryRowContext(ctx, `
SELECT pid
FROM pg_stat_activity
WHERE client_addr =
    (SELECT client_addr
     FROM pg_stat_activity
     WHERE pid = pg_backend_pid())
  AND query LIKE 'LISTEN%'
  `).Scan(&listenerPid), "Could not get listener PID")

	confirmWorkDone := func(workItemID int) {
		var state string
		row := service.db.QueryRowContext(ctx, "SELECT state FROM test_work WHERE id = $1", workItemID)
		assert.NilError(t, row.Scan(&state))
		assert.Assert(t, is.Equal(state, "done"))
	}

	workItem1ID := doTestWork()
	// Work shouldn't take longer than this
	time.Sleep(time.Second)
	confirmWorkDone(workItem1ID)
	confirmWorkDone(itemCreatedBeforeWorkerStartupWorkitemID)

	// Try to terminate the connection
	_, err := service.db.ExecContext(ctx, "SELECT pg_terminate_backend($1)", listenerPid)
	assert.NilError(t, err, "Could not terminate listener connection PID")
	// Recovery shouldn't take longer than this
	time.Sleep(2 * time.Second)

	workItem2ID := doTestWork()
	// Work shouldn't take longer than this
	time.Sleep(time.Second)
	confirmWorkDone(workItem2ID)

	cancel()
	assert.Error(t, group.Wait(), context.Canceled.Error())
}

func testGenerateAssignmentIDWithTransitionNS(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	defer func() {
		assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
	}()

	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	subnet, err := service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
	assert.NilError(t, err)

	req := getENIRequest{
		region:                        md.region,
		trunkENI:                      aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:               aws.StringValue(trunkENI.OwnerId),
		branchENIAccount:              md.account,
		subnet:                        subnet,
		securityGroups:                []string{md.defaultSecurityGroupID},
		maxIPAddresses:                50,
		maxBranchENIs:                 2,
		assignmentID:                  fmt.Sprintf("testGenerateAssignmentIDWithTransitionNS-1-%s", uuid.New().String()),
		transitionAssignmentRequested: true,
	}

	ass, err := service.generateAssignmentID(ctx, req)
	assert.NilError(t, err)

	resp, err := service.assignIPsToENI(ctx, &vpcapi.AssignIPRequestV3{
		TaskId:           req.assignmentID,
		SecurityGroupIds: req.securityGroups,
		Ipv6:             &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{},
		Ipv4:             &vpcapi.AssignIPRequestV3_TransitionRequested{},
	}, ass, 50)
	assert.NilError(t, err)
	t.Log(resp)

	var lastUsed1, lastUsed2 time.Time
	row := service.db.QueryRowContext(ctx, "SELECT transition_last_used FROM assignments WHERE id = $1", ass.transitionAssignmentID)
	assert.NilError(t, row.Scan(&lastUsed1))
	assert.Assert(t, !lastUsed1.IsZero())

	// Reset the assignment ID on req.
	req.assignmentID = fmt.Sprintf("testGenerateAssignmentIDWithTransitionNS-2-%s", uuid.New().String())
	ass2, err := service.generateAssignmentID(ctx, req)
	assert.NilError(t, err)
	assert.Assert(t, ass.transitionAssignmentID == ass2.transitionAssignmentID)
	resp2, err := service.assignIPsToENI(ctx, &vpcapi.AssignIPRequestV3{
		TaskId:           req.assignmentID,
		SecurityGroupIds: req.securityGroups,
		Ipv6:             &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{},
		Ipv4:             &vpcapi.AssignIPRequestV3_TransitionRequested{},
	}, ass2, 50)
	assert.NilError(t, err)
	t.Log(resp2)

	assert.Assert(t, cmp.Diff(resp.TransitionAssignment, resp2.TransitionAssignment, protocmp.Transform()) == "")
	row = service.db.QueryRowContext(ctx, "SELECT transition_last_used FROM assignments WHERE id = $1", ass.transitionAssignmentID)
	assert.NilError(t, row.Scan(&lastUsed2))
	assert.Assert(t, lastUsed2.After(lastUsed1))
}

func testGenerateAssignmentIDWithAddress(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}
	reconcileTrunkENILongLivedTask := service.reconcileTrunkENIsLongLivedTask()
	assert.NilError(t, service.preemptLock(ctx, item, reconcileTrunkENILongLivedTask))

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID, 3)
	assert.NilError(t, err)
	defer func() {
		assert.NilError(t, service.deleteTrunkInterface(ctx, session, aws.StringValue(trunkENI.NetworkInterfaceId)))
	}()

	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	subnet, err := service.getSubnet(ctx, aws.StringValue(trunkENI.AvailabilityZone), md.account, []string{})
	assert.NilError(t, err)

	req := getENIRequest{
		region:           md.region,
		trunkENI:         aws.StringValue(trunkENI.NetworkInterfaceId),
		trunkENIAccount:  aws.StringValue(trunkENI.OwnerId),
		branchENIAccount: md.account,
		subnet:           subnet,
		securityGroups:   []string{md.defaultSecurityGroupID},
		maxIPAddresses:   50,
		maxBranchENIs:    2,
		assignmentID:     fmt.Sprintf("testGenerateAssignmentIDWithAddress-1-%s", uuid.New().String()),
	}

	ass, err := service.generateAssignmentID(ctx, req)
	assert.NilError(t, err)

	resp, err := service.assignIPsToENI(ctx, &vpcapi.AssignIPRequestV3{
		TaskId:           req.assignmentID,
		SecurityGroupIds: req.securityGroups,
		Ipv6:             &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{},
		Ipv4:             &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{},
	}, ass, 50)
	assert.NilError(t, err)
	assert.Assert(t, resp.Ipv6Address != nil)

	req.assignmentID = fmt.Sprintf("testGenerateAssignmentIDWithAddress-2-%s", uuid.New().String())
	ass2, err := service.generateAssignmentID(ctx, req)
	assert.NilError(t, err)

	resp2, err := service.assignIPsToENI(ctx, &vpcapi.AssignIPRequestV3{
		TaskId:           req.assignmentID,
		SecurityGroupIds: req.securityGroups,
		Ipv6:             &vpcapi.AssignIPRequestV3_Ipv6AddressRequested{},
		Ipv4:             &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{},
	}, ass2, 50)
	assert.NilError(t, err)
	assert.Assert(t, resp2.Ipv6Address != nil)

	firstIP := net.ParseIP(resp.Ipv6Address.Address.Address)
	secondIP := net.ParseIP(resp2.Ipv6Address.Address.Address)
	assert.Assert(t, firstIP.String() != secondIP.String())
	ipnet := net.IPNet{
		IP:   firstIP,
		Mask: net.CIDRMask(80, 128),
	}
	assert.Assert(t, ipnet.Contains(firstIP))
	assert.Assert(t, ipnet.Contains(secondIP))
}

func testAllocateAndDeallocateStaticAddress(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	address, err := service.AllocateAddress(ctx, &titus.AllocateAddressRequest{
		AddressAllocation: &titus.AddressAllocation{
			AddressLocation: &titus.AddressLocation{
				SubnetId: md.subnetID,
			},
		},
		Family:    titus.Family_FAMILY_V4,
		AccountId: md.account,
	})
	assert.NilError(t, err)

	var count int
	var v4prefix, v6prefix string
	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM ip_addresses WHERE id = $1", address.SignedAddressAllocation.AddressAllocation.Uuid)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, count == 1)

	row = service.db.QueryRowContext(ctx, "SELECT v4prefix, v6prefix FROM ip_addresses WHERE id = $1", address.SignedAddressAllocation.AddressAllocation.Uuid)
	assert.NilError(t, row.Scan(&v4prefix, &v6prefix))

	_, err = service.DeallocateAddress(ctx, &titus.DeallocateAddressRequest{
		Uuid: address.SignedAddressAllocation.AddressAllocation.Uuid,
	})
	assert.NilError(t, err)

	row = service.db.QueryRowContext(ctx, "SELECT count(*) FROM ip_addresses WHERE id = $1", address.SignedAddressAllocation.AddressAllocation.Uuid)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, count == 0)

	subnetCIDRReservations, err := session.GetSubnetCidrReservations(ctx, md.subnetID)
	assert.NilError(t, err)
	for _, subnetCIDRReservation := range subnetCIDRReservations {
		assert.Assert(t, aws.StringValue(subnetCIDRReservation.SubnetCidrReservationId) != v4prefix)
		assert.Assert(t, aws.StringValue(subnetCIDRReservation.SubnetCidrReservationId) != v6prefix)
	}
}
