package seeds

import (
	"fmt"
	"net"
	"strings"

	"github.com/apparentlymart/go-cidr/cidr"
)

func (s Seed) SubnetUsablePrefixSeed() {
	rows, err := s.db.Query("SELECT id, cidr6 from subnets order by id")
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var (
		id    int
		cidr6 string
	)

	for rows.Next() {
		err := rows.Scan(&id, &cidr6)
		if err != nil {
			panic(err)
		}

		_, base, err := net.ParseCIDR(cidr6)
		if err != nil {
			panic(err)
		}

		var exceeded = false
		startSubnet, err := cidr.Subnet(base, 16, 0)
		if err != nil {
			panic(err)
		}

		var cidrs []interface{}
		var placeHolders []string
		count := 0
		for subnet := startSubnet; !exceeded; subnet, exceeded = cidr.NextSubnet(subnet, 80) {
			if !base.Contains(subnet.IP) {
				break
			}
			cidrs = append(cidrs, id, subnet.String())
			placeHolders = append(placeHolders, fmt.Sprintf("($%d,$%d)", count*2+1, count*2+2))
			count++
		}

		chunks := []int{0, 1, 2, 3}
		chunkSize := len(placeHolders) / len(chunks)
		for c := range chunks {
			start := c * chunkSize
			end := start + chunkSize

			stmt := fmt.Sprintf("INSERT INTO subnet_usable_prefix (subnet_id, prefix) VALUES %s", strings.Join(placeHolders[:chunkSize], ","))
			_, err = s.db.Exec(stmt, cidrs[start*2:end*2]...)
			if err != nil {
				panic(err)
			}
		}
	}
	err = rows.Err()
	if err != nil {
		panic(err)
	}
}
