package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Netflix/titus-executor/utils"

	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/Netflix/titus-executor/vpc/tool/container2"
	"github.com/apparentlymart/go-cidr/cidr"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tool/identity"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	vpctypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"
	"google.golang.org/grpc"
	//	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

var VersionInfo = version.PluginSupports("0.3.0", "0.3.1")

type Command struct {
	// Never use this context except to get the initial context for Add / Check / Del
	ctx context.Context
	iip identity.InstanceIdentityProvider
	gsv GetSharedValues
}

type config struct {
	k8sArgs utils.K8sArgs
	cfg     TitusCNIConfig

	instanceIdentity *vpcapi.InstanceIdentity

	conn *grpc.ClientConn
}

type GetSharedValues func(ctx context.Context) (*grpc.ClientConn, error)

func MakeCommand(ctx context.Context, instanceIdentityProvider identity.InstanceIdentityProvider, gsv GetSharedValues) *Command {
	return &Command{
		ctx: ctx,
		iip: instanceIdentityProvider,
		gsv: gsv,
	}
}

type TitusCNIConfig struct {
	types.NetConf
	KubeletAPIURL string `json:"KubeletAPIURL"`
}

func (c *Command) load(ctx context.Context, args *skel.CmdArgs) (*config, error) {
	ctx, span := trace.StartSpan(ctx, "load")
	defer span.End()
	// Does all the work of loading the config

	retCfg := &config{}

	err := types.LoadArgs(args.Args, &retCfg.k8sArgs)
	if err != nil {
		err = errors.Wrap(err, "Unable to parse CNI args")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	retCfg.conn, err = c.gsv(ctx)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = json.Unmarshal(args.StdinData, &retCfg.cfg)
	if err != nil {
		err = errors.Wrap(err, "Cannot parse Kubernetes configuration")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	retCfg.instanceIdentity, err = c.iip.GetIdentity(ctx)
	if err != nil {
		err = errors.Wrap(err, "Cannot retrieve instance identity")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return retCfg, nil
}

func (c *Command) getPod(ctx context.Context, cfg *config) (*corev1.Pod, error) {
	ctx, span := trace.StartSpan(ctx, "getPod")
	defer span.End()

	pod, err := utils.GetPod(ctx, cfg.cfg.KubeletAPIURL, cfg.k8sArgs)
	tracehelpers.SetStatus(err, span)
	return pod, err
}

func (c *Command) Add(args *skel.CmdArgs) error {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "Add")
	defer span.End()

	cfg, err := c.load(ctx, args)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).WithField("args", args).WithField("cfg", cfg).Info("CNI Add Networking")

	// TODO:
	// 1. Add sysctls
	// 2. Add "extrahosts"
	// 3. Configure DAD

	// Extra options we want / need
	// IPv6
	// Static IP(s)
	// Subnets
	// Account ID

	pod, err := c.getPod(ctx, cfg)
	if err != nil {
		err = errors.Wrap(err, "Unable to get pod")
		tracehelpers.SetStatus(err, span)
		return err
	}

	securityGroups, ok := pod.Annotations[vpctypes.SecurityGroupsAnnotation]
	if !ok {
		err = fmt.Errorf("Security groups must be specified on the pod via the annotation %s", vpctypes.SecurityGroupsAnnotation)
		tracehelpers.SetStatus(err, span)
		return err
	}
	span.AddAttributes(trace.StringAttribute("securityGroups", securityGroups))
	securityGroupsList := strings.Split(securityGroups, ",")

	ingressBandwidth, ok := pod.Annotations[vpctypes.IngressBandwidthAnnotation]
	if !ok {
		err = fmt.Errorf("Ingress must be specified on the pod via the annotation %s", vpctypes.IngressBandwidthAnnotation)
		tracehelpers.SetStatus(err, span)
		return err
	}
	ingressBandwidthValue, err := resource.ParseQuantity(ingressBandwidth)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse ingress bandwidth resource quantity %s", ingressBandwidth)
		tracehelpers.SetStatus(err, span)
		return err
	}

	egressBandwidth, ok := pod.Annotations[vpctypes.EgressBandwidthAnnotation]
	if !ok {
		err = fmt.Errorf("Egress must be specified on the pod via the annotation %s", vpctypes.EgressBandwidthAnnotation)
		tracehelpers.SetStatus(err, span)
		return err
	}
	egressBandwidthValue, err := resource.ParseQuantity(egressBandwidth)
	if err != nil {
		err = errors.Wrapf(err, "Cannot parse ingress bandwidth resource quantity %s", egressBandwidth)
		tracehelpers.SetStatus(err, span)
		return err
	}

	if ingressBandwidthValue.Cmp(egressBandwidthValue) != 0 {
		err = fmt.Errorf("Titus does not support differing ingress (%s) and egress (%s) bandwidth values", ingressBandwidthValue.String(), egressBandwidthValue.String())
		tracehelpers.SetStatus(err, span)
		return err
	}

	kbps := uint64(ingressBandwidthValue.Value() / 1000)

	ns, err := os.Open(args.Netns)
	if err != nil {
		err = errors.Wrapf(err, "Cannot open container netns: %s", args.Netns)
		logger.G(ctx).WithError(err).Error()
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer ns.Close()

	// FIXME(manas) This check seems redundant?
	podName := cfg.k8sArgs.K8S_POD_NAME
	podKey := utils.PodKey(pod)
	if string(podName) != podKey {
		err = fmt.Errorf("Pod key (%s) is not pod name (%s)", podKey, podName)
		logger.G(ctx).WithError(err).Error()
		tracehelpers.SetStatus(err, span)
		return err
	}
	assignIPRequest := &vpcapi.AssignIPRequestV3{
		InstanceIdentity: cfg.instanceIdentity,
		TaskId:           podKey,
		SecurityGroupIds: securityGroupsList,
		Ipv4:             &vpcapi.AssignIPRequestV3_Ipv4AddressRequested{Ipv4AddressRequested: true},
		Idempotent:       true,
	}

	client := vpcapi.NewTitusAgentVPCServiceClient(cfg.conn)

	response, err := client.AssignIPV3(ctx, assignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("AssignIP request failed")
		tracehelpers.SetStatus(err, span)
		return err
	}

	alloc := vpctypes.AssignmentToAllocation(response)

	logger.G(ctx).WithField("response", response.String()).WithField("allocation", fmt.Sprintf("%+v", alloc)).Info("Allocated IP")

	mask := net.CIDRMask(int(response.Ipv4Address.PrefixLength), 32)
	ip := net.ParseIP(response.Ipv4Address.Address.Address)
	ipnet := net.IPNet{IP: ip, Mask: mask}
	zeroIdx := 0
	gateway := cidr.Inc(ip.Mask(mask))
	logger.G(ctx).WithField("gateway", gateway).Debug("Adding default route")

	err = container2.DoSetupContainer(ctx, int(ns.Fd()), kbps, kbps, false, alloc)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Could not setup network")
		err = errors.Wrap(err, "Cannot not setup network")
		tracehelpers.SetStatus(err, span)
		return err
	}

	result := current.Result{
		CNIVersion: "0.3.1",
		Interfaces: []*current.Interface{
			{
				Name:    "eth0",
				Mac:     response.BranchNetworkInterface.MacAddress,
				Sandbox: args.Netns,
			},
		},
		IPs: []*current.IPConfig{
			{
				Version:   "4",
				Interface: &zeroIdx,
				Address:   ipnet,
				Gateway:   gateway,
			},
		},
		Routes: []*types.Route{
			{
				Dst: net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				},
				GW: gateway,
			},
		},
		DNS: types.DNS{
			// TODO
			Nameservers: []string{"169.254.169.253"},
			Domain:      "",
			Search:      nil,
			Options:     []string{"edns0", "timeout:2", "rotate"},
		},
	}

	logger.G(ctx).WithField("result", result).Debug("Created CNI allocation")

	return types.PrintResult(&result, cfg.cfg.CNIVersion)
}

func (c *Command) Check(_ *skel.CmdArgs) error {
	return nil
}

func (c *Command) Del(args *skel.CmdArgs) (e error) {
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	defer func() {
		if e != nil {
			logger.G(ctx).WithError(e).Error("Experienced error while deleting CNI setup")
		}
	}()

	ctx, span := trace.StartSpan(ctx, "Del")
	defer span.End()

	cfg, err := c.load(ctx, args)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}
	logger.G(ctx).WithField("args", args).WithField("cfg", cfg).Info("CNI Delete Networking")

	client := vpcapi.NewTitusAgentVPCServiceClient(cfg.conn)
	assignment, err := client.GetAssignment(ctx, &vpcapi.GetAssignmentRequest{
		TaskId: string(cfg.k8sArgs.K8S_POD_NAME),
	})

	if err != nil {
		// TODO: Technically, we can still delete the network interface in the container
		logger.G(ctx).WithField("taskId", string(cfg.k8sArgs.K8S_POD_NAME)).
			WithError(err).Error("Could not fetch existing assignment from VPC Service")
		err = errors.Wrap(err, "Could not fetch existing assignment from VPC Service")
		tracehelpers.SetStatus(err, span)
		return err
	}

	alloc := vpctypes.AssignmentToAllocation(assignment.Assignment)
	ns, err := os.Open(args.Netns)
	if err != nil {
		err = errors.Wrapf(err, "Cannot open container netns: %s", args.Netns)
		tracehelpers.SetStatus(err, span)
		return err
	}
	err = container2.DoTeardownContainer(ctx, alloc, int(ns.Fd()))
	_ = ns.Close()
	if err != nil {
		err = errors.Wrap(err, "Could not tear down container state")
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).Info("Successfully tore down networking")

	_, err = client.UnassignIPV3(ctx, &vpcapi.UnassignIPRequestV3{
		TaskId: string(cfg.k8sArgs.K8S_POD_NAME),
	})
	if err != nil {
		logger.G(ctx).WithError(err).Error("Cannot unassign address")
		err = errors.Wrap(err, "Cannot unassign address")
		tracehelpers.SetStatus(err, span)
		return err
	}
	logger.G(ctx).Info("Unassigned IP from VPC Service")
	return nil
}
