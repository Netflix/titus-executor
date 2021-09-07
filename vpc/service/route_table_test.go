package service

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"gotest.tools/assert"
)

func TestGenerateRouteTable(t *testing.T) {
	routeTable := ec2.RouteTable{}
	f, err := os.Open("route_table_data.json")
	assert.NilError(t, err)
	defer f.Close()
	assert.NilError(t, json.NewDecoder(f).Decode(&routeTable))

	routes := convertRouteTable(context.TODO(), &routeTable)
	assert.DeepEqual(t,
		getRoute("0.0.0.0/0", routes),
		&vpcapi.AssignIPResponseV3_Route{
			Destination: "0.0.0.0/0",
			Mtu:         1500,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv4,
		},
		cmp.Comparer(proto.Equal),
	)
	assert.DeepEqual(t,
		getRoute("::/0", routes),
		&vpcapi.AssignIPResponseV3_Route{
			Destination: "::/0",
			Mtu:         1500,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv6,
		},
		cmp.Comparer(proto.Equal),
	)

	// Test for a local route:
	assert.DeepEqual(t,
		getRoute("100.66.0.0/18", routes),
		&vpcapi.AssignIPResponseV3_Route{
			Destination: "100.66.0.0/18",
			Mtu:         0,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv4,
		},
		cmp.Comparer(proto.Equal),
	)

	// Test for a VGW:
	assert.DeepEqual(t,
		getRoute("172.27.24.0/24", routes),
		&vpcapi.AssignIPResponseV3_Route{
			Destination: "172.27.24.0/24",
			Mtu:         1500,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv4,
		},
		cmp.Comparer(proto.Equal),
	)

	// Don't generate routes for blackholes:
	assert.Assert(t, getRoute("172.28.1.0/24", routes) == nil)
}
