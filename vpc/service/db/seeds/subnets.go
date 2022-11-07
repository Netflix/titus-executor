package seeds

type dbSubnet struct {
	accountID string
	az        string
	azID      string
	cidr      string
	cidr6     string
	subnetID  string
	vpcID     string
}

func (s Seed) SubnetsSeed() {
	subnets := []dbSubnet{
		{
			accountID: "123456789012",
			az:        "us-mock-1a",
			azID:      "usm1-mock-az1",
			cidr:      "172.16.0.0/18",
			cidr6:     "fd00::/64",
			subnetID:  "subnet-mock-a",
			vpcID:     "vpc-mock-a",
		},
		{
			accountID: "123456789012",
			az:        "us-mock-1b",
			azID:      "usm1-mock-az2",
			cidr:      "172.16.64.0/18",
			cidr6:     "fd00:0000:0000:0001::/64",
			subnetID:  "subnet-mock-b",
			vpcID:     "vpc-mock-a",
		},
		{
			accountID: "123456789012",
			az:        "us-mock-1c",
			azID:      "usm1-mock-az3",
			cidr:      "172.16.128.0/18",
			cidr6:     "fd00:0000:0000:0002::/64",
			subnetID:  "subnet-mock-c",
			vpcID:     "vpc-mock-a",
		},
		{
			accountID: "123456789012",
			az:        "us-mock-1a",
			azID:      "usm1-mock-az1",
			cidr:      "172.16.192.0/18",
			cidr6:     "fd00:0000:0000:0003::/64",
			subnetID:  "subnet-mock-d", // titus
			vpcID:     "vpc-mock-a",
		},
		{
			accountID: "123456789012",
			az:        "us-mock-1b",
			azID:      "usm1-mock-az2",
			cidr:      "172.17.0.0/18",
			cidr6:     "fd00:0000:0000:0004::/64",
			subnetID:  "subnet-mock-e", // titus
			vpcID:     "vpc-mock-a",
		},
		{
			accountID: "123456789012",
			az:        "us-mock-1c",
			azID:      "usm1-mock-az3",
			cidr:      "172.17.64.0/18", // titus
			cidr6:     "fd00:0000:0000:0005::/64",
			subnetID:  "subnet-mock-f",
			vpcID:     "vpc-mock-a",
		},
	}

	for _, subnet := range subnets {
		_, err := s.db.Exec("INSERT INTO subnets(account_id, az, az_id, cidr, cidr6, subnet_id, vpc_id) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			subnet.accountID, subnet.az, subnet.azID, subnet.cidr, subnet.cidr6, subnet.subnetID, subnet.vpcID)
		if err != nil {
			panic(err)
		}
	}
}
