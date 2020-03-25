package shared

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	vpctypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/pkg/errors"
)

func AssignmentToAllocation(assignment *vpcapi.AssignIPResponseV3) vpctypes.Allocation {
	alloc := vpctypes.Allocation{
		Success:         true,
		BranchENIID:     assignment.BranchNetworkInterface.NetworkInterfaceId,
		BranchENIMAC:    assignment.BranchNetworkInterface.MacAddress,
		BranchENIVPC:    assignment.BranchNetworkInterface.VpcId,
		BranchENISubnet: assignment.BranchNetworkInterface.SubnetId,
		VlanID:          int(assignment.VlanId),
		TrunkENIID:      assignment.TrunkNetworkInterface.NetworkInterfaceId,
		TrunkENIMAC:     assignment.TrunkNetworkInterface.MacAddress,
		TrunkENIVPC:     assignment.TrunkNetworkInterface.VpcId,
		AllocationIndex: uint16(assignment.ClassId),
		DeviceIndex:     int(assignment.VlanId),
		Generation:      vpctypes.GenerationPointer(vpctypes.V3),
	}

	if assignment.Ipv6Address != nil {
		alloc.IPV6Address = assignment.Ipv6Address
	}

	if assignment.Ipv4Address != nil {
		alloc.IPV4Address = assignment.Ipv4Address
	}

	return alloc
}

func Get(ctx context.Context, url string) ([]byte, error) {
	customTransport := &http.Transport{
		MaxIdleConns: 0,
		// The certificate that the VK loads isn't reloaded periodically, so it can go stale. Therefore,
		// the easiest option is to skip verify, especially because it's on localhost.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint: gosec
	}
	client := &http.Client{
		Transport: customTransport,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Add("Accept", "application/json")
	if err != nil {
		return nil, errors.Wrap(err, "Unable to create new request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to do request")
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return ioutil.ReadAll(resp.Body)
}
