package types

import (
	"encoding/json"
	"testing"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/stretchr/testify/assert"
)

func TestFlatStringEntrypointIsParsed(t *testing.T) {
	input := `/titusimage-1.2.0/bin/titusimage -id 0e2d2a2e-1f6f-42ac-80f5-a502646423a1 -email changed@netflix.com -audience "changed test abcdefg" -description "changed test abcdefg" -type WHAT -query "set hive.auto.convert.join=false; set hive.mapred.mode=unstrict; select distinct my_id from vault.ad_dfa_dcid_profile_last_seen_d m join (select account_id, sum(standard_sanitized_duration_sec) duration from dse.loc_acct_device_ttl_sum where show_title_id = 80028732 and country_iso_code in ('FR') and region_date >= 20151227 group by account_id having duration >= 360) x on m.account_id = x.account_id where my_id != '0' and last_seen_dateint >= 20150127" -reuse true`
	expected := `["/titusimage-1.2.0/bin/titusimage", "-id", "0e2d2a2e-1f6f-42ac-80f5-a502646423a1", "-email", "changed@netflix.com", "-audience", "changed test abcdefg", "-description", "changed test abcdefg", "-type", "WHAT", "-query", "set hive.auto.convert.join=false; set hive.mapred.mode=unstrict; select distinct my_id from vault.ad_dfa_dcid_profile_last_seen_d m join (select account_id, sum(standard_sanitized_duration_sec) duration from dse.loc_acct_device_ttl_sum where show_title_id = 80028732 and country_iso_code in ('FR') and region_date >= 20151227 group by account_id having duration >= 360) x on m.account_id = x.account_id where my_id != '0' and last_seen_dateint >= 20150127", "-reuse", "true"]`

	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.EntrypointStr = &input // nolint:staticcheck
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
		taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
		assert.NoError(t, err)
		titusInfo.Process = &titus.ContainerInfo_Process{
			Entrypoint: entrypoint,
			Command:    []string{"sleep", "1"},
		}

		c, err := NewContainer(taskID, titusInfo, *resources, *conf)
		assert.NoError(t, err)

		entry, cmd := c.Process()
		assert.Len(t, entry, len(entrypoint))
		assert.Len(t, cmd, 2)
		assert.Equal(t, cmd[0], "sleep")
		assert.Equal(t, cmd[1], "1")
	}
}

func TestFlatStringEntryPointMustBeNilForCustomCmd(t *testing.T) {
	empty := ""
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	titusInfo.EntrypointStr = &empty // nolint:staticcheck
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
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	entrypoint, cmd := c.Process()
	assert.Len(t, entrypoint, 0)
	assert.Len(t, cmd, 0)
}

func TestDefaultHostnameStyle(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)

	hostname, err := ComputeHostname(c)
	assert.Nil(t, err)
	assert.Equal(t, c.TaskID(), hostname)
}

func TestEc2HostnameStyle(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[hostnameStyleParam] = "ec2"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	c.SetVPCAllocation(&vpcapi.Assignment{
		Assignment: &vpcapi.Assignment_AssignIPResponseV3{
			AssignIPResponseV3: &vpcapi.AssignIPResponseV3{
				Ipv4Address: &vpcapi.UsableAddress{
					Address: &vpcapi.Address{
						Address: "192.0.2.1",
					},
					PrefixLength: 32,
				},
			},
		},
	})
	hostname, err := ComputeHostname(c)
	assert.Nil(t, err)
	assert.Equal(t, "ip-192-0-2-1", hostname)
}

func TestInvalidHostnameStyle(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[hostnameStyleParam] = "foo"

	_, err = NewContainer(taskID, titusInfo, *resources, *conf)
	assert.Error(t, err, "unknown hostname style: foo")

	tc := &TitusInfoContainer{
		hostnameStyle: "foo",
	}
	hostname, err := ComputeHostname(tc)
	assert.Empty(t, hostname)
	assert.NotNil(t, err)
	assert.IsType(t, &InvalidConfigurationError{}, err)
}

func TestDefaultNetworkMode(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.Equal(t, titus.NetworkConfiguration_UnknownNetworkMode.String(), c.EffectiveNetworkMode())
}

func TestIPv6NetworkModeRespectsThePassthroughBool(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[assignIPv6AddressParam] = "true"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.Equal(t, titus.NetworkConfiguration_Ipv6AndIpv4.String(), c.EffectiveNetworkMode())
}

func TestTtyEnabled(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	titusInfo.PassthroughAttributes[ttyEnabledParam] = "true"

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.True(t, c.TTYEnabled())
}

func TestOomScoreAdj(t *testing.T) {
	taskID, titusInfo, resources, _, conf, err := ContainerTestArgs()
	assert.NoError(t, err)
	oomScore := int32(99)
	titusInfo.OomScoreAdj = &oomScore

	c, err := NewContainer(taskID, titusInfo, *resources, *conf)
	assert.NoError(t, err)
	assert.Equal(t, oomScore, *c.OomScoreAdj())
}
