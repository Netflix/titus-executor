package shared

import (
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

var ErrLinkNotFound = errors.New("Link not found")

func GetLinkByMac(mac string) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		if link.Attrs().HardwareAddr.String() == mac {
			return link, nil
		}
	}

	return nil, ErrLinkNotFound
}
