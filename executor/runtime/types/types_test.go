package types

import (
	"encoding/json"
	"testing"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/stretchr/testify/assert"
)

func TestFlatStringEntrypointIsParsed(t *testing.T) {
	input := `/titusimage-1.2.0/bin/titusimage -id 0e2d2a2e-1f6f-42ac-80f5-a502646423a1 -email changed@netflix.com -audience "changed test abcdefg" -description "changed test abcdefg" -type WHAT -query "set hive.auto.convert.join=false; set hive.mapred.mode=unstrict; select distinct my_id from vault.ad_dfa_dcid_profile_last_seen_d m join (select account_id, sum(standard_sanitized_duration_sec) duration from dse.loc_acct_device_ttl_sum where show_title_id = 80028732 and country_iso_code in ('FR') and region_date >= 20151227 group by account_id having duration >= 360) x on m.account_id = x.account_id where my_id != '0' and last_seen_dateint >= 20150127" -reuse true`
	expected := `["/titusimage-1.2.0/bin/titusimage", "-id", "0e2d2a2e-1f6f-42ac-80f5-a502646423a1", "-email", "changed@netflix.com", "-audience", "changed test abcdefg", "-description", "changed test abcdefg", "-type", "WHAT", "-query", "set hive.auto.convert.join=false; set hive.mapred.mode=unstrict; select distinct my_id from vault.ad_dfa_dcid_profile_last_seen_d m join (select account_id, sum(standard_sanitized_duration_sec) duration from dse.loc_acct_device_ttl_sum where show_title_id = 80028732 and country_iso_code in ('FR') and region_date >= 20151227 group by account_id having duration >= 360) x on m.account_id = x.account_id where my_id != '0' and last_seen_dateint >= 20150127", "-reuse", "true"]`

	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.EntrypointStr = &input
	titusInfo.Process = &titus.ContainerInfo_Process{
		Entrypoint: []string{"shouldBeIgnored"},
		Command:    []string{"shouldBeIgnored"},
	}

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	var expectedSlice []string
	if err := json.Unmarshal([]byte(expected), &expectedSlice); err != nil {
		t.Fatal("Can't parse expected result JSON", err)
	}

	result, cmd := c.Process()
	assert.EqualValues(t, result, expectedSlice)
	assert.Nil(t, cmd)
}

func TestCustomCmd(t *testing.T) {
	t.Run("WithNilEntrypoint", testCustomCmdWithEntrypoint(nil))
	t.Run("WithEmptyEntrypoint", testCustomCmdWithEntrypoint([]string{}))
	t.Run("WithEntrypoint", testCustomCmdWithEntrypoint([]string{"/bin/sh", "-c"}))
}

func testCustomCmdWithEntrypoint(entrypoint []string) func(*testing.T) {
	return func(t *testing.T) {
		taskID, titusInfo, resources, conf, err := ContainerTestArgs()
		assert.NoError(t, err)
		titusInfo.Process = &titus.ContainerInfo_Process{
			Entrypoint: entrypoint,
			Command:    []string{"sleep", "1"},
		}

		c, err := NewContainer(taskID, titusInfo, *resources, *conf)
		assert.NoError(t, err)

		entrypoint, cmd := c.Process()
		assert.Len(t, entrypoint, len(entrypoint))
		assert.Len(t, cmd, 2)
		assert.Equal(t, cmd[0], "sleep")
		assert.Equal(t, cmd[1], "1")
	}
}

func TestFlatStringEntryPointMustBeNilForCustomCmd(t *testing.T) {
	empty := ""
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	titusInfo.EntrypointStr = &empty
	titusInfo.Process = &titus.ContainerInfo_Process{
		Entrypoint: []string{"will be", "ignored"},
		Command:    []string{"this", "one", "too"},
	}
	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	entrypoint, cmd := c.Process()
	assert.Len(t, entrypoint, 0)
	assert.Len(t, cmd, 0)
}

func TestDefaultIsNil(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	entrypoint, cmd := c.Process()
	assert.Len(t, entrypoint, 0)
	assert.Len(t, cmd, 0)
}

func TestDefaultHostnameStyle(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	hostname, err := c.ComputeHostname()
	assert.Nil(t, err)
	assert.Equal(t, c.TaskID(), hostname)
}

func TestEc2HostnameStyle(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[hostnameStyleParam] = "ec2"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	c.SetVPCAllocation(&vpcTypes.HybridAllocation{
		IPV4Address: &vpcapi.UsableAddress{
			PrefixLength: 32,
			Address: &vpcapi.Address{
				Address: "1.2.3.4"},
		},
	})

	hostname, err := c.ComputeHostname()
	assert.Nil(t, err)
	assert.Equal(t, "ip-1-2-3-4", hostname)
}

func TestInvalidHostnameStyle(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[hostnameStyleParam] = "foo"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	hostname, err := c.ComputeHostname()
	assert.Empty(t, hostname)
	assert.NotNil(t, err)
	assert.IsType(t, &InvalidConfigurationError{}, err)
}

func TestDefaultIPv6AddressAssignment(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.False(t, c.AssignIPv6Address())
}

func TestIPv6AddressAssignment(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[assignIPv6AddressParam] = "true"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.True(t, c.AssignIPv6Address())
}

func TestTtyEnabled(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[ttyEnabledParam] = "true"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.True(t, c.TTYEnabled())
}

func TestOomScoreAdj(t *testing.T) {
	taskID, titusInfo, resources, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	oomScore := int32(99)
	titusInfo.OomScoreAdj = &oomScore

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.Equal(t, oomScore, *c.OomScoreAdj())
}
