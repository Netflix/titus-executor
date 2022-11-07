package seeds

type dbTrunkEni struct {
	trunkEni   string
	accountID  string
	az         string
	generation int
	mac        string
	region     string
	subnetID   string
	vpcID      string
}

func (s Seed) TrunkEniSeed() {
	trunkEnis := []dbTrunkEni{
		{
			trunkEni:   "eni-mock-trunk",
			accountID:  "123456789012",
			az:         "us-mock-1a",
			generation: 3,
			mac:        "01:23:45:67:89:ab",
			region:     "us-mock-1",
			subnetID:   "subnet-mock-a",
			vpcID:      "vpc-mock-a",
		},
	}

	for _, eni := range trunkEnis {
		row := s.db.QueryRow("INSERT INTO trunk_enis(trunk_eni, account_id, az, generation, mac, region, subnet_id, vpc_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
			eni.trunkEni, eni.accountID, eni.az, eni.generation, eni.mac, eni.region, eni.subnetID, eni.vpcID)

		var id int
		err := row.Scan(&id)
		if err != nil {
			panic(err)
		}

		_, err = s.db.Exec("INSERT INTO htb_classid(trunk_eni, class_id) SELECT $1, generate_series(10010, 11000) ON CONFLICT DO NOTHING", id)
		if err != nil {
			panic(err)
		}
	}
}
