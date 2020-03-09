package service

import (
	"context"
	"database/sql"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/aws/aws-sdk-go/aws"
	"github.com/Netflix/titus-executor/aws/aws-sdk-go/service/ec2"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"k8s.io/apimachinery/pkg/util/sets"
)

var enableIntegrationTests bool
var dbURL string
var integrationTestTimeout time.Duration
var testAZ, testAccount, testSecurityGroupID string

func TestMain(m *testing.M) {
	flag.BoolVar(&enableIntegrationTests, "enable-integration-tests", false, "Enable running integration tests")
	flag.StringVar(&dbURL, "db-url", "", "Database URL")
	flag.DurationVar(&integrationTestTimeout, "integration-test-timeout", 5*time.Minute, "The maximum amount of time a single integration test can take")
	flag.StringVar(&testAZ, "az", "", "The AZ to us for the test")
	flag.StringVar(&testAccount, "account", "", "The account ID to use for the test")
	flag.StringVar(&testSecurityGroupID, "security-group", "", "The security group id to use for testing")
	flag.Parse()
	os.Exit(m.Run())
}

type integrationTestMetadata struct {
	region   string
	account  string
	az       string
	vpc      string
	subnetID string

	defaultSecurityGroupID string
	testSecurityGroupID    string
}

func newTestServiceInstance(t *testing.T) *vpcService {
	connector, err := pq.NewConnector(dbURL)
	assert.NilError(t, err)

	hostname, err := os.Hostname()
	assert.NilError(t, err)
	db := sql.OpenDB(connector)
	assert.NilError(t, db.Ping())
	return &vpcService{
		db:       db,
		dbURL:    dbURL,
		hostname: hostname,
		ec2:      ec2wrapper.NewEC2SessionManager(),
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
	runIntegrationTest(t, "testAssociateWithDelayFaultInMainline", testAssociateWithDelayFaultInMainline)
	runIntegrationTest(t, "testReconcileBranchENIAttachments", testReconcileBranchENIAttachments)
}

type integrationTestFunc func(context.Context, *testing.T, integrationTestMetadata, *vpcService, *ec2wrapper.EC2Session)

func runIntegrationTest(tParent *testing.T, testName string, testFunction integrationTestFunc) {
	tParent.Run(testName, func(t *testing.T) {
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
		}

		row := svc.db.QueryRowContext(ctx, "SELECT region FROM availability_zones WHERE zone_name = $1 AND account_id = $2 LIMIT 1", testAZ, testAccount)
		assert.NilError(t, row.Scan(&md.region))

		row = svc.db.QueryRowContext(ctx, "SELECT vpc_id, subnet_id FROM subnets WHERE az = $1 AND account_id = $2 LIMIT 1", testAZ, testAccount)
		assert.NilError(t, row.Scan(&md.vpc, &md.subnetID))

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
	eni, err := service.createNewTrunkENI(ctx, session, &md.subnetID)
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
		Description: aws.String(vpc.BranchNetworkInterfaceDescription),
		SubnetId:    aws.String(md.subnetID),
	})
	assert.NilError(t, err)
	logger.G(ctx).WithField("eni", aws.StringValue(dangling.NetworkInterface.NetworkInterfaceId)).Debug("Created test dangling branch ENI")

	var nullSGinDB, differentSGInDB, nonExistentSGs *ec2.NetworkInterface

	var id int
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM branch_enis WHERE branch_eni = 'eni-055a2f17c777132a4'")
		assert.NilError(t, err)
		row := tx.QueryRowContext(ctx, `
INSERT INTO branch_enis(branch_eni, account_id, subnet_id, az, vpc_id) VALUES ('eni-055a2f17c777132a4', $1, $2, $3, $4)
RETURNING id
`, md.account, md.subnetID, md.az, md.vpc)
		assert.NilError(t, row.Scan(&id))

		nullSGinDB, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		assert.NilError(t, err)
		logger.G(ctx).WithField("eni", aws.StringValue(nullSGinDB.NetworkInterfaceId)).Debug("Created test ENI with null SGs in DB")
		_, err = tx.ExecContext(ctx, "UPDATE branch_enis SET security_groups = NULL WHERE branch_eni = $1", aws.StringValue(nullSGinDB.NetworkInterfaceId))
		assert.NilError(t, err)

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
	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_enis WHERE branch_eni = $1", aws.StringValue(dangling.NetworkInterface.NetworkInterfaceId))
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 1))

	row = service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_enis WHERE id = $1", id)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 0))

	var securityGroups []string
	row = service.db.QueryRowContext(ctx, "SELECT security_groups FROM branch_enis WHERE branch_eni = $1", aws.StringValue(nullSGinDB.NetworkInterfaceId))
	assert.NilError(t, row.Scan(pq.Array(&securityGroups)))
	// This only works because there is one, otherwise if they are in different orders it will break
	// So, if you want to do this with multiple SGs, either sort them, or turn them into a string set
	assert.DeepEqual(t, []string{md.defaultSecurityGroupID}, securityGroups)

	row = service.db.QueryRowContext(ctx, "SELECT security_groups FROM branch_enis WHERE branch_eni = $1", aws.StringValue(nonExistentSGs.NetworkInterfaceId))
	assert.NilError(t, row.Scan(pq.Array(&securityGroups)))
	assert.DeepEqual(t, []string{md.defaultSecurityGroupID}, securityGroups)

	output, err := session.DescribeNetworkInterfaces(ctx, ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []*string{differentSGInDB.NetworkInterfaceId},
	})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(output.NetworkInterfaces, 1))
	assert.Assert(t, is.Len(output.NetworkInterfaces[0].Groups, 1))
	assert.Assert(t, is.Equal(aws.StringValue(output.NetworkInterfaces[0].Groups[0].GroupId), md.testSecurityGroupID))
}

func testAssociateWithDelayFaultInMainline(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	t.Parallel()
	// This one is a little bit more scary because of what can go wrong if the associate worker is not running
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	associateWorker := service.associateActionWorker()
	disassociateWorker := service.disassociateActionWorker()
	nilItems, err := nilItemEnumerator(ctx)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(nilItems, 1))

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		return service.preemptLock(groupCtx, nilItems[0], associateWorker.longLivedTask())
	})
	group.Go(func() error {
		return service.preemptLock(groupCtx, nilItems[0], disassociateWorker.longLivedTask())
	})

	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID)
	assert.NilError(t, err)
	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	var branchENI *ec2.NetworkInterface
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		branchENI, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		return err
	}))

	assoc := association{
		branchENI: aws.StringValue(branchENI.NetworkInterfaceId),
		trunkENI:  aws.StringValue(trunkENI.NetworkInterfaceId),
	}

	assert.NilError(t, group.Wait())
	group.Go(func() error {
		return associateWorker.loop(ctx, nilItems[0])
	})

	group.Go(func() error {
		return disassociateWorker.loop(ctx, nilItems[0])
	})

	/* This will only effect the associate / disassociate calls that happen in "mainline" */
	ctx = registerFault(ctx, associateFaultKey, func(ctx context.Context) error {
		time.Sleep(5 * time.Second)
		return nil
	})
	ctx = registerFault(ctx, disassociateFaultKey, func(ctx context.Context) error {
		time.Sleep(5 * time.Second)
		return nil
	})

	var associationID string
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "SELECT branch_eni FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", aws.StringValue(branchENI.NetworkInterfaceId))
		assert.NilError(t, err)
		id, err := service.associateNetworkInterface(ctx, tx, session, assoc, 5)
		assert.NilError(t, err)
		associationID = *id
		return nil
	}))

	logger.G(ctx).WithField("associationID", associationID).Debug("Completed association")
	cancel()
	assert.Error(t, group.Wait(), context.Canceled.Error())
}

func testAssociate(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	t.Parallel()
	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID)
	assert.NilError(t, err)
	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	var branchENI *ec2.NetworkInterface
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		branchENI, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		return err
	}))

	assoc := association{
		branchENI: aws.StringValue(branchENI.NetworkInterfaceId),
		trunkENI:  aws.StringValue(trunkENI.NetworkInterfaceId),
	}
	var associationID string
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "SELECT branch_eni FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", aws.StringValue(branchENI.NetworkInterfaceId))
		assert.NilError(t, err)
		id, err := service.associateNetworkInterface(ctx, tx, session, assoc, 5)
		assert.NilError(t, err)
		associationID = *id
		return nil
	}))

	logger.G(ctx).WithField("associationID", associationID).Debug("Completed association")

	output, err := session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice([]string{associationID}),
	})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(output.InterfaceAssociations, 1))

	// Now disassociate
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "SELECT branch_eni FROM branch_enis WHERE branch_eni = $1 FOR NO KEY UPDATE", aws.StringValue(branchENI.NetworkInterfaceId))
		assert.NilError(t, err)
		assert.NilError(t, service.disassociateNetworkInterface(ctx, tx, session, associationID, false))
		return nil
	}))

	_, err = session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: aws.StringSlice([]string{associationID}),
	})
	assert.Assert(t, err != nil)
	awsErr := ec2wrapper.RetrieveEC2Error(err)
	assert.Assert(t, is.Equal(awsErr.Code(), ec2wrapper.InvalidAssociationIDNotFound))

	var count int
	row := service.db.QueryRowContext(ctx, "SELECT count(*) FROM branch_eni_attachments WHERE association_id = $1", associationID)
	assert.NilError(t, row.Scan(&count))
	assert.Assert(t, is.Equal(count, 0))
}

func testReconcileBranchENIAttachments(ctx context.Context, t *testing.T, md integrationTestMetadata, service *vpcService, session *ec2wrapper.EC2Session) {
	trunkENI, err := service.createNewTrunkENI(ctx, session, &md.subnetID)
	assert.NilError(t, err)
	logger.G(ctx).WithField("trunkENI", trunkENI.String()).Debug("Created test trunk ENI")

	item := &regionAccount{
		region:    md.region,
		accountID: md.account,
	}

	assert.NilError(t, service.preemptLock(ctx, item, service.reconcileBranchENIAttachmentsLongLivedTask()))

	var branchENI *ec2.NetworkInterface
	assert.NilError(t, withTransaction(ctx, service.db, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		branchENI, err = service.createBranchENI(ctx, tx, session, md.subnetID, []string{md.defaultSecurityGroupID})
		return err
	}))

	association, err := session.AssociateTrunkInterface(ctx, ec2.AssociateTrunkInterfaceInput{
		BranchInterfaceId: branchENI.NetworkInterfaceId,
		TrunkInterfaceId:  trunkENI.NetworkInterfaceId,
		VlanId:            aws.Int64(5),
	})
	assert.NilError(t, err)

	assert.NilError(t, service.reconcileBranchAttachmentsENIsForRegionAccount(ctx, item))

	_, err = session.DescribeTrunkInterfaceAssociations(ctx, ec2.DescribeTrunkInterfaceAssociationsInput{
		AssociationIds: []*string{association.InterfaceAssociation.AssociationId},
	})
	awsErr := ec2wrapper.RetrieveEC2Error(err)
	assert.Assert(t, awsErr != nil)
	assert.Assert(t, is.Equal(awsErr.Code(), ec2wrapper.InvalidAssociationIDNotFound))
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
