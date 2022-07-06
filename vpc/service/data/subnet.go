package data

import "fmt"

type Subnet struct {
	ID        int
	Az        string
	VpcID     string
	AccountID string
	SubnetID  string
	Cidr      string
	Region    string
}

func (s *Subnet) Key() string {
	return fmt.Sprintf("%s_%s_%s", s.Region, s.AccountID, s.SubnetID)
}

func (s *Subnet) String() string {
	return fmt.Sprintf("Subnet{id=%d vpc=%s, az=%s, subnet=%s, account=%s}",
		s.ID, s.VpcID, s.Az, s.SubnetID, s.AccountID)
}
