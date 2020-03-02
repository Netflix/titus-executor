package cni

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	//	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

// These are the names of the annotations we use on the pod to configure
const (
	securityGroupsAnnotation   = "com.netflix.titus.network/securityGroups"
	ingressBandwidthAnnotation = "kubernetes.io/ingress-bandwidth"
	egressBandwidthAnnotation  = "kubernetes.io/egress-bandwidth"
)

var VersionInfo = version.PluginSupports("0.3.0", "0.3.1")

type Command struct {
	// Never use this context except to get the initial context for Add / Check / Del
	ctx context.Context
	iip identity.InstanceIdentityProvider
	gsv GetSharedValues
}

type config struct {
	k8sArgs K8sArgs
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

// Borrowed from: https://github.com/Tanujparihar/aws/blob/87052b192d468fab20bbf4c10590dc2a39885680/plugins/routed-eni/cni.go
type K8sArgs struct {
	types.CommonArgs

	// K8S_POD_NAME is pod's name
	K8S_POD_NAME types.UnmarshallableString // nolint:golint

	// K8S_POD_NAMESPACE is pod's namespace
	K8S_POD_NAMESPACE types.UnmarshallableString // nolint:golint

	// K8S_POD_INFRA_CONTAINER_ID is pod's container id
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString // nolint:golint
}

type TitusCNIConfig struct {
	types.NetConf

	KubeletAPIURL string `json:"KubeletAPIURL"`
}

func assignmentToAllocation(assignment *vpcapi.AssignIPResponseV3) vpctypes.Allocation {
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
		DeviceIndex:     int(assignment.VlanId),
		AllocationIndex: uint16(assignment.ClassId),
	}

	if assignment.Ipv6Address != nil {
		alloc.IPV6Address = assignment.Ipv6Address
	}

	if assignment.Ipv4Address != nil {
		alloc.IPV4Address = assignment.Ipv4Address
	}

	return alloc
}

func getKey(args K8sArgs) string {
	return fmt.Sprintf("%s/%s", args.K8S_POD_NAMESPACE, args.K8S_POD_NAME)
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

func getPod(ctx context.Context, cfg *config) (*corev1.Pod, error) {
	ctx, span := trace.StartSpan(ctx, "getPod")
	defer span.End()
	// Borrowed from: https://gist.github.com/nownabe/4345d9b68f323ba30905c9dfe3460006

	// https://godoc.org/k8s.io/apimachinery/pkg/runtime#Scheme
	scheme := runtime.NewScheme()

	// https://godoc.org/k8s.io/apimachinery/pkg/runtime/serializer#CodecFactory
	codecFactory := serializer.NewCodecFactory(scheme)

	// https://godoc.org/k8s.io/apimachinery/pkg/runtime#Decoder
	deserializer := codecFactory.UniversalDeserializer()

	// Borrowed from: https://stackoverflow.com/questions/12122159/how-to-do-a-https-request-with-bad-certificate
	customTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // nolint:gosec
	}

	client := &http.Client{Transport: customTransport}
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.cfg.KubeletAPIURL, nil)
	if err != nil {
		err = errors.Wrapf(err, "Cannot create HTTP request to fetch pods at %s", cfg.cfg.KubeletAPIURL)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	ret, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "Cannot fetch pod pod list from kubelet at %s", cfg.cfg.KubeletAPIURL)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer ret.Body.Close()

	body, err := ioutil.ReadAll(ret.Body)
	if err != nil {
		err = errors.Wrap(err, "Cannot read body from Kubelet")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	podListObject, _, err := deserializer.Decode(body, nil, &corev1.PodList{})
	if err != nil {
		err = errors.Wrap(err, "Cannot deserialize podlist from kubelet")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	// I think this works?
	podList := podListObject.(*corev1.PodList)

	namespace := string(cfg.k8sArgs.K8S_POD_NAMESPACE)
	name := string(cfg.k8sArgs.K8S_POD_NAME)
	for idx := range podList.Items {
		pod := podList.Items[idx]
		if pod.Namespace == namespace && pod.Name == name {
			return &pod, nil
		}
	}

	err = fmt.Errorf("Could not find pod %s, in namespace %s", name, namespace)
	tracehelpers.SetStatus(err, span)
	return nil, err
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

	// TODO:
	// 1. Add sysctls
	// 2. Add "extrahosts"
	// 3. Configure DAD

	// Extra options we want / need
	// IPv6
	// Static IP(s)
	// Subnets
	// Account ID

	pod, err := getPod(ctx, cfg)
	if err != nil {
		err = errors.Wrap(err, "Unable to get pod")
		tracehelpers.SetStatus(err, span)
		return err
	}
	securityGroups, ok := pod.Annotations[securityGroupsAnnotation]
	if !ok {
		return fmt.Errorf("Security groups must be specified on the pod via the annotation %s", securityGroupsAnnotation)
	}
	span.AddAttributes(trace.StringAttribute("securityGroups", securityGroups))
	securityGroupsList := strings.Split(securityGroups, ",")

	ingressBandwidth, ok := pod.Annotations[ingressBandwidthAnnotation]
	if !ok {
		return fmt.Errorf("Ingress must be specified on the pod via the annotation %s", ingressBandwidthAnnotation)
	}
	ingressBandwidthValue, err := resource.ParseQuantity(ingressBandwidth)
	if err != nil {
		return errors.Wrapf(err, "Cannot parse ingress bandwidth resource quantity %s", ingressBandwidth)
	}

	egressBandwidth, ok := pod.Annotations[egressBandwidthAnnotation]
	if !ok {
		return fmt.Errorf("Egress must be specified on the pod via the annotation %s", ingressBandwidthAnnotation)
	}
	egressBandwidthValue, err := resource.ParseQuantity(egressBandwidth)
	if err != nil {
		return errors.Wrapf(err, "Cannot parse ingress bandwidth resource quantity %s", egressBandwidth)
	}

	if ingressBandwidthValue.Cmp(egressBandwidthValue) != 0 {
		return fmt.Errorf("Titus does not support differing ingress (%s) and egress (%s) bandwidth values", ingressBandwidthValue.String(), egressBandwidthValue.String())
	}

	kbps := uint64(ingressBandwidthValue.Value() / 1000)

	ns, err := os.Open(args.Netns)
	if err != nil {
		err = errors.Wrapf(err, "Cannot open container netns: %s", args.Netns)
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer ns.Close()

	assignIPRequest := &vpcapi.AssignIPRequestV3{
		InstanceIdentity: cfg.instanceIdentity,
		TaskId:           getKey(cfg.k8sArgs),
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

	alloc := assignmentToAllocation(response)

	logger.G(ctx).WithField("response", response.String()).WithField("allocation", fmt.Sprintf("%+v", alloc)).Info("Allocated IP")

	mask := net.CIDRMask(int(response.Ipv4Address.PrefixLength), 32)
	ip := net.ParseIP(response.Ipv4Address.Address.Address)
	ipnet := net.IPNet{IP: ip, Mask: mask}
	zeroIdx := 0
	gateway := cidr.Inc(ip.Mask(mask))
	logger.G(ctx).WithField("gateway", gateway).Debug("Adding default route")

	_, err = container2.DoSetupContainer(ctx, int(ns.Fd()), kbps, kbps, false, alloc)
	if err != nil {
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

	return types.PrintResult(&result, cfg.cfg.CNIVersion)
}

func (c *Command) Check(_ *skel.CmdArgs) error {
	return nil
}

func (c *Command) Del(args *skel.CmdArgs) (e error) {
	defer time.Sleep(5 * time.Second) // This is so logs can get out, because CNI silently swallows deletion failures
	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	defer func() {
		if e != nil {
			logger.G(ctx).WithError(e).Error("Experienced error while deleting CNI setup")
		}
	}()

	ctx, span := trace.StartSpan(ctx, "Del")
	defer span.End()
	logger.G(ctx).WithField("args", args).Info("CNI Delete Networking")

	cfg, err := c.load(ctx, args)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return err
	}

	ns, err := os.Open(args.Netns)
	if err != nil {
		err = errors.Wrapf(err, "Cannot open container netns: %s", args.Netns)
		tracehelpers.SetStatus(err, span)
		return err
	}
	defer ns.Close()

	unassignIPRequest := &vpcapi.UnassignIPRequestV3{
		TaskId:            getKey(cfg.k8sArgs),
		IncludeAssignment: true,
	}

	client := vpcapi.NewTitusAgentVPCServiceClient(cfg.conn)
	unassignIPResponse, err := client.UnassignIPV3(ctx, unassignIPRequest)
	if err != nil {
		logger.G(ctx).WithError(err).Error("Cannot unassign address")
		err = errors.Wrap(err, "Cannot unassign address")
		tracehelpers.SetStatus(err, span)
		return err
	}

	alloc := assignmentToAllocation(unassignIPResponse.Assignment)
	logger.G(ctx).WithField("alloc", alloc).Info("Unassigned IP from VPC Service")
	err = container2.DoTeardownContainer(ctx, alloc, int(ns.Fd()))
	if err != nil {
		err = errors.Wrap(err, "Could not tear down container state")
		tracehelpers.SetStatus(err, span)
		return err
	}

	logger.G(ctx).Info("Successfully tore down networking")

	return nil
}
