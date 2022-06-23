package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	vpcTypes "github.com/Netflix/titus-executor/vpc/types"
	"github.com/hashicorp/go-multierror"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	defaultNetworkBandwidthBps = 128 * MB
	vpctoolTimeout             = 45 * time.Second
)

// This will setup c.Allocation
func prepareNetworkDriver(ctx context.Context, cfg Config, c runtimeTypes.Container) (cleanupFunc, error) { // nolint: gocyclo
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, vpctoolTimeout)
	defer cancel()

	ctx, span := trace.StartSpan(ctx, "prepareNetworkDriver")
	defer span.End()

	log.Printf("Configuring VPC network for %s", c.TaskID())

	eniIdx := c.NormalizedENIIndex()
	if eniIdx == nil {
		err := errors.New("could not determine normalized ENI index for container")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	sgIDs := c.SecurityGroupIDs()
	if sgIDs == nil {
		err := errors.New("container is missing security groups")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	bandwidthBps := int64(defaultNetworkBandwidthBps)
	if bwLim := c.IngressBandwidthLimitBps(); bwLim != nil && *bwLim != 0 {
		bandwidthBps = *bwLim
	}

	args := []string{
		"assign",
		"--device-idx", strconv.Itoa(*eniIdx),
		"--security-groups", strings.Join(*sgIDs, ","),
		"--task-id", c.TaskID(),
		"--bandwidth", strconv.FormatInt(bandwidthBps, 10),
		"--network-mode", c.EffectiveNetworkMode(), // TODO: Deal with HighScale mode either here, or use the effective mode (which is fallback)
	}

	if c.SignedAddressAllocationUUID() != nil {
		args = append(args, "--ipv4-allocation-uuid", *c.SignedAddressAllocationUUID())
	}

	if c.VPCAccountID() != nil {
		args = append(args, "--interface-account", *c.VPCAccountID())
	}

	if c.SubnetIDs() != nil {
		args = append(args, "--subnet-ids", strings.Join(*c.SubnetIDs(), ","))
	}

	if c.ElasticIPPool() != nil {
		args = append(args, "--elastic-ip-pool", *c.ElasticIPPool())
	}

	if c.ElasticIPs() != nil {
		args = append(args, "--elastic-ips", *c.ElasticIPs())
	}

	if c.UseJumboFrames() {
		args = append(args, "--jumbo=true")
	}

	if c.AllowNetworkBursting() {
		args = append(args, "--burst=true")
	}

	// There's a narrow chance that there's a race here that the context expires, but the assignment has
	// been successful, but we didn't read it. the GC should loop back around and fix it.
	allocationCommand := exec.CommandContext(ctx, vpcToolPath(), args...) // nolint: gosec
	stderrPipe, err := allocationCommand.StderrPipe()
	if err != nil {
		err = fmt.Errorf("Could not setup stderr pipe for allocation command: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	stdoutPipe, err := allocationCommand.StdoutPipe()
	if err != nil {
		err = errors.Wrap(err, "Could not setup stdout pipe for allocation command")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = allocationCommand.Start()
	if err != nil {
		err = errors.Wrap(err, "Could not start allocation command")
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	var result vpcapi.VPCToolResult
	var errs *multierror.Error
	data, err := ioutil.ReadAll(stdoutPipe)
	if err != nil {
		errs = multierror.Append(errs, fmt.Errorf("Could not read from stdout pipe: %w", err))
	} else {
		if len(data) == 0 {
			errs = multierror.Append(errs, fmt.Errorf("vpctool had no stdout output to parse"))
		} else {
			err = protojson.Unmarshal(data, &result)
			if err != nil {
				errs = multierror.Append(errs, fmt.Errorf("Could not read / deserialize JSON (%s) from assignment command: %w", string(data), err))
			}
		}
	}
	if errs != nil {
		errs = multierror.Append(errs, allocationCommand.Process.Signal(unix.SIGQUIT))
		data, err = ioutil.ReadAll(stderrPipe)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("Could not read stderr: %w", err))
		} else {
			errs = multierror.Append(errs, fmt.Errorf("stderr output: %s", string(data)))
		}
		errs = multierror.Append(errs, fmt.Errorf("Error waiting on allocation command after %s (timeout %s): %w", time.Since(start), vpctoolTimeout, allocationCommand.Wait()))
		tracehelpers.SetStatus(errs, span)
		return nil, errs
	}
	switch t := result.Result.(type) {
	case *vpcapi.VPCToolResult_Error:
		log.WithField("error", t.Error.Error).Error("VPC Configuration error")
		if (strings.Contains(t.Error.Error, "invalid security groups requested for vpc id")) ||
			(strings.Contains(t.Error.Error, "InvalidGroup.NotFound") ||
				(strings.Contains(t.Error.Error, "InvalidSecurityGroupID.NotFound")) ||
				(strings.Contains(t.Error.Error, "Security groups not found"))) {
			var invalidSg runtimeTypes.InvalidSecurityGroupError
			invalidSg.Reason = errors.New(t.Error.Error)
			return nil, &invalidSg
		}
		err = fmt.Errorf("vpc network configuration error: %s", t.Error.Error)
		tracehelpers.SetStatus(err, span)
		return nil, err
	case *vpcapi.VPCToolResult_Assignment:
		c.SetVPCAllocation(t.Assignment)
	default:
		err = fmt.Errorf("Unknown type: %t", t)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	err = allocationCommand.Wait()
	if err != nil {
		err = fmt.Errorf("Allocation command exited with unexpected error: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		unassignCommand := exec.CommandContext(ctx, vpcToolPath(), "unassign", "--task-id", c.TaskID()) // nolint: gosec
		err := unassignCommand.Run()
		if err != nil {
			log.WithError(err).Error("Experienced error unassigning v3 allocation")
			return errors.Wrap(err, "Could not unassign task IP address")
		}
		return nil
	}, nil
}

func setupNetworking(ctx context.Context, burst bool, c runtimeTypes.Container, cred ucred) (cleanupFunc, error) { // nolint: gocyclo
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	log.Info("Setting up container network")
	var result vpcTypes.WiringStatus

	pid1DirPath := filepath.Join("proc", strconv.Itoa(int(cred.pid)))
	pid1DirFile, err := os.Open(pid1DirPath)
	if err != nil {
		return nil, err
	}
	defer shouldClose(pid1DirFile)

	setupCommand := exec.CommandContext(ctx, vpcToolPath(), "setup-container", "--pid-1-dir-fd", "3") // nolint: gosec
	stdin, err := setupCommand.StdinPipe()
	if err != nil {
		return nil, err // nolint: vet
	}
	stdout, err := setupCommand.StdoutPipe()
	if err != nil {
		return nil, err
	}

	setupCommand.Stderr = os.Stderr
	setupCommand.ExtraFiles = []*os.File{pid1DirFile}

	err = setupCommand.Start()
	if err != nil {
		return nil, errors.Wrap(err, "Could not start setup command")
	}

	allocation := c.VPCAllocation()
	marshaler := protojson.MarshalOptions{
		Indent: "\t",
	}
	data, err := marshaler.Marshal(allocation)
	if err != nil {
		return nil, err
	}

	_, err = stdin.Write(data)
	if err != nil {
		return nil, fmt.Errorf("Could not write data to stdin pipe of setup container: %w", err)
	}

	if err := json.NewDecoder(stdout).Decode(&result); err != nil {
		return nil, fmt.Errorf("Unable to read json from pipe during setup-container: %+v", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("titus-vpc-tool error: %s", result.Error)
	}

	netnsPath := filepath.Join("/proc/", strconv.Itoa(int(cred.pid)), "ns", "net")
	f2, err := os.Open(netnsPath)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to open container network namespace file")
	}
	return func() error {
		return teardownCommand(f2, allocation)
	}, nil

}

func (r *DockerRuntime) computeDNSServers() []string {
	switch r.c.EffectiveNetworkMode() {
	case titus.NetworkConfiguration_Ipv6AndIpv4.String():
		// True dual stack means we should provide both
		return []string{"fd00:ec2::253", "169.254.169.253"}
	case titus.NetworkConfiguration_Ipv6AndIpv4Fallback.String():
		// IPv6 with fallback means we only want v6 resolvers, which reduces
		// the burden on TSA for ipv4 udp traffic
		return []string{"fd00:ec2::253"}
	case titus.NetworkConfiguration_Ipv6Only.String():
		// If we're ipv6-only and running the SystemDNS local resolver
		// which provides DNS64, we'll point to that
		if runtimeTypes.ShouldStartSystemDNS(&r.cfg, r.c) {
			return []string{"127.0.0.53"}
		}
		// otherwise return the EC2 IPv6 resolver
		return []string{"fd00:ec2::253"}
	default:
		// Any other situation means we can return the classic v4 resolver
		return []string{"169.254.169.253"}
	}
}
