package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"

	tt "github.com/Netflix/titus-executor/executor/runtime/types"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func main() {
	log.Debug(os.Args)

	if len(os.Args) < 6 {
		log.Fatal("enough arguments not provided")
	}

	ociRuntimePath := os.Args[1]
	passThroughArg := os.Args[2:]

	stat, err := os.Stat(ociRuntimePath)
	if err != nil {
		log.Fatal(errors.Wrapf(err, "cannot access oci runtime at %s", ociRuntimePath))
	}
	if !(stat.Mode().IsRegular() && stat.Mode()&0100 == 0100) {
		log.Fatalf("oci runtime at %s is not an executable file", ociRuntimePath)
	}

	for idx, arg := range passThroughArg {
		if arg == "--bundle" {
			if idx < len(passThroughArg)-1 {
				log.Fatal("no bundle path was given")
			}
			if err = processBundle(passThroughArg[idx+1]); err != nil {
				log.Fatal(err)
			}
		}
	}

	cmd := exec.Command(ociRuntimePath, passThroughArg...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs)

	err = cmd.Start()
	if err != nil {
		log.Fatal(errors.Wrapf(err, "error executing oci runtime %s", cmd))
	}

	// forward signals to oci runtime
	go func() {
		for sig := range sigs {
			_ = cmd.Process.Signal(sig)
		}
	}()

	err = cmd.Wait()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if code, ok := exit.Sys().(syscall.WaitStatus); ok {
				os.Exit(code.ExitStatus())
			}
		}
		log.Fatal(err)
	}
	os.Exit(0)
}

func processBundle(bundlePath string) error {
	configPath := path.Join(bundlePath, "config.json")

	bytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return errors.Wrapf(err, "cannot read bundle config %s", configPath)
	}

	var spec specs.Spec
	if err = json.Unmarshal(bytes, &spec); err != nil {
		return errors.Wrapf(err, "cannot unmarshal %s as oci bundle", configPath)
	}

	log.Debugf("original %v", spec)
	err = addNetflixEnvironment(&spec)
	if err != nil {
		return errors.Wrapf(err, "error accessing environment")
	}
	log.Debugf("modified %v", spec)

	bytes, err = json.Marshal(spec)
	if err != nil {
		return errors.Wrapf(err, "cannot marshal %s as oci bundle", string(bytes))
	}

	err = ioutil.WriteFile(configPath, bytes, 0600)
	if err != nil {
		return errors.Wrapf(err, "cannot write bundle config %s", configPath)
	}

	return nil
}

func addNetflixEnvironment(spec *specs.Spec) error {
	spec.Process.Env = copyFromHost(spec.Process.Env)
	spec.Process.Env = addStaticEnv(spec.Process.Env)

	return setFromCni(spec)

}

func setFromCni(spec *specs.Spec) error {

	// NOTE(manas) see if this is specified anywhere
	var podName string
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace {
			podName = path.Base(ns.Path)
		}
	}

	if podName == "" {
		// do nothing if we cannot determine pod
		return errors.New("cannot find pod name from namespaces")
	}

	fname := path.Join(tt.TitusEnvironmentsDir, podName, "vpc-v3.json")

	bytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return errors.Wrapf(err, "error reading %s", fname)
	}

	var response vpcapi.AssignIPResponseV3

	err = json.Unmarshal(bytes, &response)
	if err != nil {
		return errors.Wrapf(err, "%s is not AssignIPResponseV3", fname)
	}

	cniEnv := map[string]string{
		"EC2_LOCAL_IPV4":   response.Ipv4Address.Address.Address,
		"EC2_IPV6S":        response.Ipv6Address.Address.Address,
		"EC2_INTERFACE_ID": response.BranchNetworkInterface.NetworkInterfaceId,
		"EC2_VPC_ID":       response.BranchNetworkInterface.VpcId,
	}

	for k, v := range cniEnv {
		spec.Process.Env = append(spec.Process.Env, fmt.Sprintf("%s=%s", k, v))
	}

	return nil
}

func addStaticEnv(env []string) []string {
	static := []string{
		"NETFLIX_APPUSER=appuser",
		"EC2_DOMAIN=amazonaws.com",
		/* https://docs.aws.amazon.com/cli/latest/topic/config-vars.html
		 * https://github.com/jtblin/kube2iam/issues/31
		 */
		"AWS_METADATA_SERVICE_TIMEOUT=5",
		"AWS_METADATA_SERVICE_NUM_ATTEMPTS=3",
	}

	return append(env, static...)
}

func copyFromHost(env []string) []string {
	keys := []string{
		"NETFLIX_ENVIRONMENT",
		"NETFLIX_ACCOUNT",
		"NETFLIX_STACK",
		"EC2_INSTANCE_ID",
		"EC2_REGION",
		"EC2_AVAILABILITY_ZONE",
		"EC2_OWNER_ID",
		"EC2_RESERVATION_ID",
	}

	for _, k := range keys {
		v := os.Getenv(k)

		// Add agent's stack as TITUS_STACK so platform libraries can
		// determine agent stack, if needed.
		if k == "NETFLIX_STACK" {
			k = "TITUS_STACK"
		}
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	return env
}
