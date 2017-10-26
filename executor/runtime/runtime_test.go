package runtime

import (
	"encoding/json"
	"testing"

	"github.com/Netflix/titus-executor/api/netflix/titus"
)

var fixtures = []*struct {
	input    string
	expected string // JSON
}{
	{
		input:    `/titusimage-1.2.0/bin/titusimage -id 0e2d2a2e-1f6f-42ac-80f5-a502646423a1 -email changed@netflix.com -audience "changed test abcdefg" -description "changed test abcdefg" -type WHAT -query "set hive.auto.convert.join=false; set hive.mapred.mode=unstrict; select distinct my_id from vault.ad_dfa_dcid_profile_last_seen_d m join (select account_id, sum(standard_sanitized_duration_sec) duration from dse.loc_acct_device_ttl_sum where show_title_id = 80028732 and country_iso_code in ('FR') and region_date >= 20151227 group by account_id having duration >= 360) x on m.account_id = x.account_id where my_id != '0' and last_seen_dateint >= 20150127" -reuse true`,
		expected: `["/titusimage-1.2.0/bin/titusimage", "-id", "0e2d2a2e-1f6f-42ac-80f5-a502646423a1", "-email", "changed@netflix.com", "-audience", "changed test abcdefg", "-description", "changed test abcdefg", "-type", "WHAT", "-query", "set hive.auto.convert.join=false; set hive.mapred.mode=unstrict; select distinct my_id from vault.ad_dfa_dcid_profile_last_seen_d m join (select account_id, sum(standard_sanitized_duration_sec) duration from dse.loc_acct_device_ttl_sum where show_title_id = 80028732 and country_iso_code in ('FR') and region_date >= 20151227 group by account_id having duration >= 360) x on m.account_id = x.account_id where my_id != '0' and last_seen_dateint >= 20150127", "-reuse", "true"]`,
	},
}

func TestEntrypointParse(t *testing.T) {
	for _, f := range fixtures {
		var titusInfo titus.ContainerInfo
		titusInfo.EntrypointStr = &f.input
		var expected []string
		if err := json.Unmarshal([]byte(f.expected), &expected); err != nil {
			t.Fatal("Can't parse expected result JSON", err)
		}
		result, err := GetEntrypointFromProto(&titusInfo)
		if err != nil {
			t.Fatalf("Can't parse entrypoint %q: %v", *titusInfo.EntrypointStr, err)
		}
		for i := range result {
			if result[i] != expected[i] {
				t.Fatal("Unexpected result at index", i, "got", result[i],
					"expected", expected[i])
			}
		}
	}
}
