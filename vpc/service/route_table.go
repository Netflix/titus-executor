package service

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/service/ec2wrapper"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/hashicorp/go-multierror"
	"go.opencensus.io/trace"
)

const tableAssociated = "associated"

// monitor route tables loop populates the internal routesCache -> route table.
// This can then be used
func (vpcService *vpcService) monitorRouteTableLoop(ctx context.Context) {
	src := rand.New(rand.NewSource(time.Now().UnixNano())) // nolint: gosec
	err := vpcService.monitorRouteTables(ctx)
	if err != nil {
		logger.G(ctx).WithError(err).Error("First route table monitoring attempt failed!")
	}
	for {
		// This is executed for the first time via the first assign IP
		// Sleep between 3-5 minutes
		err = waitFor(ctx, 3*time.Minute+time.Duration(src.Int31n(120))*time.Second)
		if err != nil {
			logger.G(ctx).WithError(err).Info("Route table monitor loop ending")
			return
		}

		err = vpcService.monitorRouteTables(ctx)
		if err != nil {
			logger.G(ctx).WithError(err).Error("Route table monitoring attempt failed!")
		}
	}
}

func (vpcService *vpcService) monitorRouteTables(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "monitorRouteTables")
	defer span.End()

	subnets, err := vpcService.getSubnets(ctx)
	if err != nil {
		err = fmt.Errorf("Cannot fetch subnets: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	keys := map[ec2wrapper.Key][]*subnet{}
	for idx := range subnets {
		s := subnets[idx].(*subnet)
		key := ec2wrapper.Key{
			AccountID: s.accountID,
			Region:    s.region,
		}
		keys[key] = append(keys[key], s)
	}

	group := multierror.Group{}
	for i := range keys {
		key := i
		group.Go(func() error {
			accountRegionSubnets := keys[key]
			err := vpcService.monitorRouteTable(ctx, key, accountRegionSubnets)
			if err != nil {
				logger.G(ctx).WithFields(map[string]interface{}{
					"region":    key.Region,
					"accountID": key.AccountID,
				}).Error("Could not route tables for account / region")
			}
			return err
		})
	}

	err = group.Wait().ErrorOrNil()
	if err != nil {
		err = fmt.Errorf("Could not populate route cache: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	return nil
}

func (vpcService *vpcService) monitorRouteTable(ctx context.Context, key ec2wrapper.Key, subnets []*subnet) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "monitorRouteTable")
	defer span.End()
	span.AddAttributes(
		trace.StringAttribute("region", key.Region),
		trace.StringAttribute("accountID", key.AccountID),
	)

	session, err := vpcService.ec2.GetSessionFromAccountAndRegion(ctx, key)
	if err != nil {
		err = fmt.Errorf("Could not get session for %s: %w", key.String(), err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	routeTables, err := session.GetRouteTables(ctx)
	if err != nil {
		err = fmt.Errorf("Cannot fetch route tables: %w", err)
		tracehelpers.SetStatus(err, span)
		return err
	}

	merr := &multierror.Error{}
	for _, s := range subnets {
		routeTable := getRouteTable(s, routeTables)
		if routeTable != nil {
			vpcService.routesCache.Store(s.subnetID, convertRouteTable(ctx, routeTable))
		} else {
			logger.G(ctx).WithField("subnet", s.subnetID).Error("Could not find route table")
			merr = multierror.Append(merr, fmt.Errorf("Could not determine route table for subnet %s", s.subnetID))
		}
	}

	err = merr.ErrorOrNil()
	tracehelpers.SetStatus(err, span)
	return err
}

func convertRouteTable(ctx context.Context, table *ec2.RouteTable) []*vpcapi.AssignIPResponseV3_Route {
	routes := []*vpcapi.AssignIPResponseV3_Route{}
	for _, route := range table.Routes {
		customRoute, err := getCustomRoute(route)
		if customRoute != nil {
			routes = append(routes, customRoute)
		}
		if err != nil {
			logger.G(ctx).WithError(err).WithField("route", route.String()).Warning("Could not process route")
		}
	}

	/* Always create a default route, even if it doesn't exist. */
	if getRoute("0.0.0.0/0", routes) == nil {
		routes = append(routes, &vpcapi.AssignIPResponseV3_Route{
			Destination: "0.0.0.0/0",
			Mtu:         1500,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv4,
		})
	}

	if getRoute("::/0", routes) == nil {
		routes = append(routes, &vpcapi.AssignIPResponseV3_Route{
			Destination: "::/0",
			Mtu:         1500,
			Family:      vpcapi.AssignIPResponseV3_Route_IPv6,
		})
	}

	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Destination < routes[j].Destination
	})

	return routes
}

func getRoute(destination string, routes []*vpcapi.AssignIPResponseV3_Route) *vpcapi.AssignIPResponseV3_Route {
	for _, route := range routes {
		if route.Destination == destination {
			return route
		}
	}

	return nil
}

func getCustomRoute(route *ec2.Route) (*vpcapi.AssignIPResponseV3_Route, error) {
	if aws.StringValue(route.State) != "active" {
		return nil, nil
	}

	vpcroute := &vpcapi.AssignIPResponseV3_Route{
		Family: -1,
	}

	gateway := aws.StringValue(route.GatewayId)
	if route.TransitGatewayId != nil {
		// https://docs.aws.amazon.com/vpc/latest/tgw/transit-gateway-quotas.html#mtu-quota
		// The maximum transmission unit (MTU) of a network connection is the size, in bytes, of the largest permissible packet that can be passed over the connection. The larger the MTU of a connection, the more data that can be passed in a single packet. A transit gateway supports an MTU of 8500 bytes for traffic between VPCs, Direct Connect gateway, and peering attachments. Traffic over VPN connections can have an MTU of 1500 bytes.
		//
		// Packets with a size larger than 8500 bytes that arrive at the transit gateway are dropped.
		vpcroute.Mtu = 8500
	} else if gateway == "local" ||
		route.VpcPeeringConnectionId != nil {
		// Allow the MTU to be the default MTU for local connectivity
	} else if route.EgressOnlyInternetGatewayId != nil ||
		strings.HasPrefix(gateway, "igw-") ||
		route.NatGatewayId != nil ||
		strings.HasPrefix(gateway, "vgw-") ||
		strings.HasPrefix(gateway, "eigw-") {
		vpcroute.Mtu = 1500
	} else {
		return nil, nil
	}

	var ipnet *net.IPNet
	var err error
	if route.DestinationCidrBlock != nil {
		vpcroute.Family = vpcapi.AssignIPResponseV3_Route_IPv4
		_, ipnet, err = net.ParseCIDR(aws.StringValue(route.DestinationCidrBlock))
	} else if route.DestinationIpv6CidrBlock != nil {
		vpcroute.Family = vpcapi.AssignIPResponseV3_Route_IPv6
		_, ipnet, err = net.ParseCIDR(aws.StringValue(route.DestinationIpv6CidrBlock))
	} else {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	// Normalization
	vpcroute.Destination = ipnet.String()

	// Validate the resultant route:
	if vpcroute.Destination == "" {
		return nil, fmt.Errorf("route has invalid destination: %s", vpcroute.Destination)
	}

	if vpcroute.Family != vpcapi.AssignIPResponseV3_Route_IPv4 && vpcroute.Family != vpcapi.AssignIPResponseV3_Route_IPv6 {
		return nil, fmt.Errorf("route has invalid family: %s", vpcroute.Family.String())
	}

	if vpcroute.Mtu != 0 && (vpcroute.Mtu < 1280 || vpcroute.Mtu > 9001) {
		return nil, fmt.Errorf("route has invalid mtu: %d", vpcroute.Mtu)
	}

	return vpcroute, nil
}

func getRouteTable(s *subnet, routeTables []*ec2.RouteTable) *ec2.RouteTable {
	// This has a couple short-comings:
	// * If there are multiple route tables somehow associated with a single subnet, it wont work.
	// * If route tables are in a middle-state of associating / disassociating, it wont work.

	// First try to see if there are any explicitly associated route tables.
	for idx := range routeTables {
		routeTable := routeTables[idx]
		for _, association := range routeTable.Associations {
			if aws.StringValue(association.SubnetId) == s.subnetID &&
				association.AssociationState != nil &&
				aws.StringValue(association.AssociationState.State) == tableAssociated {
				return routeTable
			}
		}
	}

	// Ugh.
	for idx := range routeTables {
		routeTable := routeTables[idx]
		for _, association := range routeTable.Associations {
			if aws.BoolValue(association.Main) {
				if aws.StringValue(routeTable.VpcId) == s.vpcID &&
					association.AssociationState != nil &&
					aws.StringValue(association.AssociationState.State) == tableAssociated {
					return routeTable
				}
			}
		}
	}

	return nil
}
