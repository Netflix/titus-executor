package seeds

type dbAvailabilityZone struct {
	account_id           string
	group_name           string
	network_border_group string
	region               string
	zone_id              string
	zone_name            string
}

func (s Seed) AvailabilityZoneSeed() {
	availabilityZones := []dbAvailabilityZone{
		{
			account_id:           "123456789012",
			group_name:           "us-mock-1",
			network_border_group: "us-mock-1",
			region:               "us-mock-1",
			zone_id:              "usm1-mock-az1",
			zone_name:            "us-mock-1a",
		},
		{
			account_id:           "123456789012",
			group_name:           "us-mock-1",
			network_border_group: "us-mock-1",
			region:               "us-mock-1",
			zone_id:              "usm1-mock-az2",
			zone_name:            "us-mock-1b",
		},
		{
			account_id:           "123456789012",
			group_name:           "us-mock-1",
			network_border_group: "us-mock-1",
			region:               "us-mock-1",
			zone_id:              "usm1-mock-az3",
			zone_name:            "us-mock-1c",
		},
	}

	for _, az := range availabilityZones {
		_, err := s.db.Exec("INSERT INTO availability_zones(account_id, group_name, network_border_group, region, zone_id, zone_name) VALUES ($1, $2, $3, $4, $5, $6)",
			az.account_id, az.group_name, az.network_border_group, az.region, az.zone_id, az.zone_name)
		if err != nil {
			panic(err)
		}
	}
}
