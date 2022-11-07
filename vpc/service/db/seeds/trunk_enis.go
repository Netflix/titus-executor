package seeds

type dbTrunkEni struct {
	trunk_eni  string
	account_id string
	az         string
	generation int
	mac        string
	region     string
	subnet_id  string
	vpc_id     string
}

func (s Seed) TrunkEniSeed() {
	trunkEnis := []dbTrunkEni{
		{
			trunk_eni:  "eni-mock-trunk",
			account_id: "123456789012",
			az:         "us-mock-1a",
			generation: 3,
			mac:        "01:23:45:67:89:ab",
			region:     "us-mock-1",
			subnet_id:  "subnet-mock-a",
			vpc_id:     "vpc-mock-a",
		},
	}

	for _, eni := range trunkEnis {
		row := s.db.QueryRow("INSERT INTO trunk_enis(trunk_eni, account_id, az, generation, mac, region, subnet_id, vpc_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
			eni.trunk_eni, eni.account_id, eni.az, eni.generation, eni.mac, eni.region, eni.subnet_id, eni.vpc_id)

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
