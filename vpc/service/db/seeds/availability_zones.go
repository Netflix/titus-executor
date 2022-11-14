package seeds

type dbAvailabilityZone struct {
	accountID          string
	groupName          string
	networkBorderGroup string
	region             string
	zoneID             string
	zoneName           string
}

func (s Seed) AvailabilityZoneSeed() {
	availabilityZones := []dbAvailabilityZone{
		{
			accountID:          "123456789012",
			groupName:          "us-mock-1",
			networkBorderGroup: "us-mock-1",
			region:             "us-mock-1",
			zoneID:             "usm1-mock-az1",
			zoneName:           "us-mock-1a",
		},
		{
			accountID:          "123456789012",
			groupName:          "us-mock-1",
			networkBorderGroup: "us-mock-1",
			region:             "us-mock-1",
			zoneID:             "usm1-mock-az2",
			zoneName:           "us-mock-1b",
		},
		{
			accountID:          "123456789012",
			groupName:          "us-mock-1",
			networkBorderGroup: "us-mock-1",
			region:             "us-mock-1",
			zoneID:             "usm1-mock-az3",
			zoneName:           "us-mock-1c",
		},
	}

	for _, az := range availabilityZones {
		_, err := s.db.Exec("INSERT INTO availability_zones(account_id, group_name, network_border_group, region, zone_id, zone_name) VALUES ($1, $2, $3, $4, $5, $6)",
			az.accountID, az.groupName, az.networkBorderGroup, az.region, az.zoneID, az.zoneName)
		if err != nil {
			panic(err)
		}
	}
}
