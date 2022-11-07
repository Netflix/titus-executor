package seeds

import (
	"fmt"
)

type scrPrefix struct {
	prefix      string
	_type       string
	description string
}

type dbSubnetCidrReservationV6 struct {
	subnetID string
	prefixes []scrPrefix
}

func (s Seed) SubnetCidrReservationV6Seed() {
	scrs := []dbSubnetCidrReservationV6{
		{
			subnetID: "1",
			prefixes: []scrPrefix{
				{prefix: "fd00::e000:0:0:0/67", _type: "prefix", description: "None"},
				{prefix: "fd00::d000:0:0:0/68", _type: "prefix", description: "None"},
				{prefix: "fd00::c800:0:0:0/69", _type: "prefix", description: "None"},
				{prefix: "fd00::c400:0:0:0/70", _type: "prefix", description: "None"},
				{prefix: "fd00::c200:0:0:0/71", _type: "prefix", description: "None"},
				{prefix: "fd00::c100:0:0:0/72", _type: "prefix", description: "None"},
				{prefix: "fd00::c0e0:0:0:0/75", _type: "prefix", description: "None"},
				{prefix: "fd00::c0df:0:0:0/80", _type: "prefix", description: "None"},
				{prefix: "fd00::c0de:0:0:0/80", _type: "explicit", description: "v6assigner-reserved"},
				{prefix: "fd00::c0dc:0:0:0/79", _type: "prefix", description: "None"},
				{prefix: "fd00::c0d8:0:0:0/78", _type: "prefix", description: "None"},
				{prefix: "fd00::c0d0:0:0:0/77", _type: "prefix", description: "None"},
				{prefix: "fd00::c0c0:0:0:0/76", _type: "prefix", description: "None"},
				{prefix: "fd00::c080:0:0:0/74", _type: "prefix", description: "None"},
				{prefix: "fd00::c000:0:0:0/73", _type: "prefix", description: "None"},
				{prefix: "fd00::8000:0:0:0/66", _type: "prefix", description: "None"},
				{prefix: "fd00::4000:0:0:0/66", _type: "prefix", description: "None"},
				{prefix: "fd00::2000:0:0:0/67", _type: "prefix", description: "None"},
				{prefix: "fd00::1000:0:0:0/68", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00::800:0:0:0/69", _type: "prefix", description: "None"},
				{prefix: "fd00::400:0:0:0/70", _type: "prefix", description: "None"},
				{prefix: "fd00::200:0:0:0/71", _type: "prefix", description: "None"},
				{prefix: "fd00::100:0:0:0/72", _type: "prefix", description: "None"},
				{prefix: "fd00::80:0:0:0/73", _type: "prefix", description: "None"},
				{prefix: "fd00::40:0:0:0/74", _type: "prefix", description: "None"},
				{prefix: "fd00::20:0:0:0/75", _type: "prefix", description: "None"},
				{prefix: "fd00::10:0:0:0/76", _type: "prefix", description: "None"},
				{prefix: "fd00::8:0:0:0/77", _type: "prefix", description: "None"},
				{prefix: "fd00::4:0:0:0/78", _type: "prefix", description: "None"},
				{prefix: "fd00::2:0:0:0/79", _type: "prefix", description: "None"},
				{prefix: "fd00::1:0:0:0/80", _type: "prefix", description: "None"},
			},
		},
		{
			subnetID: "2",
			prefixes: []scrPrefix{
				{prefix: "fd00:0:0:1:e000::/67", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:d000::/68", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c800::/69", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c400::/70", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c200::/71", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c100::/72", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c0e0::/75", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c0df::/80", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c0de::/80", _type: "explicit", description: "v6assigner-reserved"},
				{prefix: "fd00:0:0:1:c0dc::/79", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c0d8::/78", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c0d0::/77", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c0c0::/76", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c080::/74", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:c000::/73", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:8000::/66", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:4000::/66", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:2000::/67", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:1000::/68", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:1:800::/69", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:400::/70", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:200::/71", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:100::/72", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:80::/73", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:40::/74", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:20::/75", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:10::/76", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:8::/77", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:4::/78", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:2::/79", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:1:1::/80", _type: "prefix", description: "None"},
			},
		},
		{
			subnetID: "3",
			prefixes: []scrPrefix{
				{prefix: "fd00:0:0:2:e000::/67", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:d000::/68", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c800::/69", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c400::/70", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c200::/71", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c100::/72", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c0e0::/75", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c0df::/80", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c0de::/80", _type: "explicit", description: "v6assigner-reserved"},
				{prefix: "fd00:0:0:2:c0dc::/79", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c0d8::/78", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c0d0::/77", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c0c0::/76", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c080::/74", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:c000::/73", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:8000::/66", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:4000::/66", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:2000::/67", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:1000::/68", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:2:800::/69", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:400::/70", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:200::/71", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:100::/72", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:80::/73", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:40::/74", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:20::/75", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:10::/76", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:8::/77", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:4::/78", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:2::/79", _type: "prefix", description: "None"},
				{prefix: "fd00:0:0:2:1::/80", _type: "prefix", description: "None"},
			},
		},
		{
			subnetID: "4",
			prefixes: []scrPrefix{
				{prefix: "fd00:0:0:3:8000::/65", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:4000::/66", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:2000::/67", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:1000::/68", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:800::/69", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:400::/70", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:200::/71", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:100::/72", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:80::/73", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:40::/74", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:20::/75", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:10::/76", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:8::/77", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:4::/78", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:2::/79", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:3:1::/80", _type: "explicit", description: "titus-reserved"},
			},
		},
		{
			subnetID: "5",
			prefixes: []scrPrefix{
				{prefix: "fd00:0:0:4:8000::/65", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:4000::/66", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:2000::/67", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:1000::/68", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:800::/69", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:400::/70", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:200::/71", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:100::/72", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:80::/73", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:40::/74", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:20::/75", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:10::/76", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:8::/77", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:4::/78", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:2::/79", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:4:1::/80", _type: "explicit", description: "titus-reserved"},
			},
		},
		{
			subnetID: "6",
			prefixes: []scrPrefix{
				{prefix: "fd00:0:0:5:8000::/65", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:4000::/66", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:2000::/67", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:1000::/68", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:800::/69", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:400::/70", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:200::/71", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:100::/72", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:80::/73", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:40::/74", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:20::/75", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:10::/76", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:8::/77", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:4::/78", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:2::/79", _type: "explicit", description: "titus-reserved"},
				{prefix: "fd00:0:0:5:1::/80", _type: "explicit", description: "titus-reserved"},
			},
		},
	}

	for _, reservation := range scrs {
		count := 0
		for _, prefix := range reservation.prefixes {
			count++
			scrID := fmt.Sprintf("scr-%s00000000000000%0d", reservation.subnetID, count)
			_, err := s.db.Exec("INSERT INTO subnet_cidr_reservations_v6(reservation_id, subnet_id, prefix, type, description) VALUES ($1, $2, $3, $4, $5)",
				scrID, reservation.subnetID, prefix.prefix, prefix._type, prefix.description)
			if err != nil {
				panic(err)
			}
		}
	}
}
