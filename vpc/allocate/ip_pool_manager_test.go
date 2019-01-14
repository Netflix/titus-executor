package allocate

import (
	"context"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Netflix/titus-executor/fslocker"
	vpcContext "github.com/Netflix/titus-executor/vpc/context"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeMac = "fake-mac"

var (
	_ ec2wrapper.NetworkInterface = (*testNetworkInterface)(nil)
)

type testNetworkInterface struct {
	ipv4Addresses []string
	freeIPs       func([]string) error
	refresh       func() error
}

func (tni *testNetworkInterface) FreeIPv4Addresses(ctx context.Context, _ client.ConfigProvider, deallocationList []string) error {
	if tni.freeIPs != nil {
		return tni.freeIPs(deallocationList)
	}
	panic("Free IPs not implemented")
}

func (*testNetworkInterface) GetDeviceNumber() int {
	panic("implement me")
}

func (*testNetworkInterface) GetInterfaceID() string {
	panic("implement me")
}

func (*testNetworkInterface) GetSubnetID() string {
	panic("implement me")
}

func (*testNetworkInterface) GetMAC() string {
	return fakeMac
}

func (*testNetworkInterface) GetSecurityGroupIds() map[string]struct{} {
	panic("implement me")
}

func (tni *testNetworkInterface) GetIPv4Addresses() []string {
	return tni.ipv4Addresses
}

func (tni *testNetworkInterface) Refresh() error {
	if tni.refresh != nil {
		return tni.refresh()
	}
	panic("Refresh not implemented")
}

func testFreeIPsOneIP(t *testing.T, ctx *vpcContext.VPCContext, tni *testNetworkInterface, ipPoolManager *IPPoolManager) {
	tni.ipv4Addresses = []string{"1.2.3.4"}
	assert.NoError(t, ipPoolManager.DoGc(ctx, time.Second))
	assert.NoError(t, ipPoolManager.DoGc(ctx, time.Second))
	time.Sleep(3 * time.Second)
	assert.NoError(t, ipPoolManager.DoGc(ctx, time.Second))
}

func testFreeIPsTwoIP(t *testing.T, ctx *vpcContext.VPCContext, tni *testNetworkInterface, ipPoolManager *IPPoolManager) {
	ipPoolManager.ipRefreshSleepInterval = 0
	var ipList = []string{"1.2.3.4", "5.6.7.8", "9.8.10.11"}
	called := false
	tries := 3
	// Force 3 tries before IPs go away
	tni.refresh = func() error {
		if tries > 0 {
			tni.ipv4Addresses = ipList[:1]
		}
		tries--
		return nil
	}
	tni.freeIPs = func(deallocationList []string) error {
		called = true
		assert.Equal(t, ipList[1:], deallocationList)
		return nil
	}
	tni.ipv4Addresses = ipList
	assert.NoError(t, ipPoolManager.DoGc(ctx, time.Second))
	assert.NoError(t, ipPoolManager.DoGc(ctx, time.Second))
	time.Sleep(3 * time.Second)
	assert.NoError(t, ipPoolManager.DoGc(ctx, time.Second))
	assert.True(t, called)
}

func TestIPPoolManager(t *testing.T) {
	testFunctions := []func(*testing.T, *vpcContext.VPCContext, *testNetworkInterface, *IPPoolManager){
		testFreeIPsOneIP,
		testFreeIPsTwoIP,
	}
	for _, fun := range testFunctions {
		fullName := runtime.FuncForPC(reflect.ValueOf(fun).Pointer()).Name()
		splitName := strings.Split(fullName, ".")
		funName := splitName[len(splitName)-1]
		testName := strings.Title(funName)
		t.Run(testName, makeTestParallel(wrapTest(fun)))
	}
}

func makeTestParallel(f func(*testing.T)) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		f(t)
	}
}

func wrapTest(fun func(*testing.T, *vpcContext.VPCContext, *testNetworkInterface, *IPPoolManager)) func(*testing.T) {
	return func(t2 *testing.T) {
		tni := &testNetworkInterface{}
		ipPoolManager := NewIPPoolManager(tni)
		dir, err := ioutil.TempDir("", "fs-locker")
		require.NoError(t2, err)

		locker, err := fslocker.NewFSLocker(dir)
		require.NoError(t2, err)

		defer func() {
			require.NoError(t2, os.RemoveAll(dir))
		}()
		logger := logrus.New()
		logger.Level = logrus.DebugLevel

		ctx := &vpcContext.VPCContext{
			Context:  context.Background(),
			Logger:   logrus.NewEntry(logger),
			FSLocker: locker,
		}
		fun(t2, ctx, tni, ipPoolManager)
	}
}
