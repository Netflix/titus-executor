package seeds

type dbSubnet struct {
	account_id string
	az         string
	az_id      string
	cidr       string
	cidr6      string
	subnet_id  string
	vpc_id     string
}

func (s Seed) SubnetsSeed() {
	subnets := []dbSubnet{
		{
			account_id: "123456789012",
			az:         "us-mock-1a",
			az_id:      "usm1-mock-az1",
			cidr:       "172.16.0.0/18",
			cidr6:      "fd00::/64",
			subnet_id:  "subnet-mock-a",
			vpc_id:     "vpc-mock-a",
		},
		{
			account_id: "123456789012",
			az:         "us-mock-1b",
			az_id:      "usm1-mock-az2",
			cidr:       "172.16.64.0/18",
			cidr6:      "fd00:0000:0000:0001::/64",
			subnet_id:  "subnet-mock-b",
			vpc_id:     "vpc-mock-a",
		},
		{
			account_id: "123456789012",
			az:         "us-mock-1c",
			az_id:      "usm1-mock-az3",
			cidr:       "172.16.128.0/18",
			cidr6:      "fd00:0000:0000:0002::/64",
			subnet_id:  "subnet-mock-c",
			vpc_id:     "vpc-mock-a",
		},
		{
			account_id: "123456789012",
			az:         "us-mock-1a",
			az_id:      "usm1-mock-az1",
			cidr:       "172.16.192.0/18",
			cidr6:      "fd00:0000:0000:0003::/64",
			subnet_id:  "subnet-mock-d", // titus
			vpc_id:     "vpc-mock-a",
		},
		{
			account_id: "123456789012",
			az:         "us-mock-1b",
			az_id:      "usm1-mock-az2",
			cidr:       "172.17.0.0/18",
			cidr6:      "fd00:0000:0000:0004::/64",
			subnet_id:  "subnet-mock-e", // titus
			vpc_id:     "vpc-mock-a",
		},
		{
			account_id: "123456789012",
			az:         "us-mock-1c",
			az_id:      "usm1-mock-az3",
			cidr:       "172.17.64.0/18", // titus
			cidr6:      "fd00:0000:0000:0005::/64",
			subnet_id:  "subnet-mock-f",
			vpc_id:     "vpc-mock-a",
		},
	}

	for _, subnet := range subnets {
		_, err := s.db.Exec("INSERT INTO subnets(account_id, az, az_id, cidr, cidr6, subnet_id, vpc_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			subnet.account_id, subnet.az, subnet.az_id, subnet.cidr, subnet.cidr6, subnet.subnet_id, subnet.vpc_id)
		if err != nil {
			panic(err)
		}
	}
}
