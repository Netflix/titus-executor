// +build linux

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"

	"github.com/Netflix/titus-executor/utils/k8s"

	"github.com/golang/protobuf/proto" // nolint: staticcheck
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	tt "github.com/Netflix/titus-executor/executor/runtime/types"
	mt "github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	v1 "k8s.io/api/core/v1"
)

const kubeletAPIPodsURL = "https://localhost:10250/pods"

func getPrev(args *skel.CmdArgs) (*current.Result, error) {
	var cfg types.NetConf

	err := json.Unmarshal(args.StdinData, &cfg)
	if err != nil {
		err = errors.Wrap(err, "Cannot parse cni configuration")
		return nil, err
	}

	err = version.ParsePrevResult(&cfg)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing prevResult")
	}

	prev, err := current.NewResultFromResult(cfg.PrevResult)
	if err != nil {
		return nil, errors.Wrap(err, "error casting prevResult")
	}
	logrus.Debugf("prevResult %#v", prev)

	return prev, err
}

func getPodName(args *skel.CmdArgs) (string, error) {
	var k8sArgs k8s.Args
	err := types.LoadArgs(args.Args, &k8sArgs)
	if err != nil {
		return "pod-name", errors.Wrap(err, "Unable to parse CNI k8s args")
	}
	logrus.Debugf("k8s args %#v", k8sArgs)

	return string(k8sArgs.K8S_POD_NAME), nil
}

func getPod(args *skel.CmdArgs) (*v1.Pod, error) {
	var k8sArgs k8s.Args
	err := types.LoadArgs(args.Args, &k8sArgs)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse CNI k8s args")
	}
	logrus.Debugf("k8s args %#v", k8sArgs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	return k8s.GetPod(ctx, kubeletAPIPodsURL, k8sArgs)
}

func extractEnv(prev *current.Result, pod *v1.Pod) (map[string]string, error) {
	env := map[string]string{}

	env["LISTEN_PORT"] = "80"

	env["PEER_NAMESPACE"] = getPeerNsPath(pod.Name)
	env["EC2_REGION"] = os.Getenv("EC2_REGION")

	var ok bool

	for _, ip := range prev.IPs {
		switch ip.Version {
		case "4":
			env["EC2_LOCAL_IPV4"] = ip.Address.String()
			ok = true
		case "6":
			env["EC2_IPV6S"] = ip.Address.String()
			ok = true
		}
	}

	if !ok {
		return nil, errors.New("No IP information in chained CNI result")
	}

	// pod specific configuration
	env["TITUS_TASK_INSTANCE_ID"] = pod.Name

	env["TITUS_IAM_ROLE"] = pod.Annotations[mt.IamRoleArnAnnotation]
	env["X_FORWARDED_FOR_BLOCKING_MODE"] = pod.Annotations[mt.XForwardedForBlockingModeAnnotation]

	return env, nil
}

func setupEnv(pod *v1.Pod, env map[string]string) error {
	err := writeEnvFile(pod, env)
	if err != nil {
		return errors.Wrap(err, "Unable to write environment file")
	}

	metatronEnv := env[mt.TitusMetatronVariableName]

	if len(metatronEnv) == 0 {
		return nil
	}

	metatronOn, err := strconv.ParseBool(metatronEnv)
	if err != nil {
		return errors.Wrap(err, "Unable to tell if metatron is enabled")
	}

	if !metatronOn {
		return nil
	}

	err = writeContainerInfo(pod)
	if err != nil {
		return errors.Wrap(err, "Unable to write containerInfo file")
	}

	return nil
}

func writeEnvFile(pod *v1.Pod, env map[string]string) error {
	fd, err := openFile(path.Join(tt.TitusEnvironmentsDir, pod.Name), "titus-imds-proxy.env")
	if err != nil {
		return err
	}

	for key, val := range env {
		qval := strconv.QuoteToASCII(val)

		_, err := fmt.Fprintf(fd, "%s=%s\n", key, qval)
		if err != nil {
			return err
		}
	}

	return fd.Close()
}

func writeNetworkNamespaceFile(pod *v1.Pod, networkNamespaceName string) error {
	fd, err := openFile(path.Join(tt.TitusEnvironmentsDir, pod.Name), "netns")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(fd, "%s", networkNamespaceName)
	if err != nil {
		return err
	}

	return fd.Close()
}

func openFile(dname, fname string) (*os.File, error) {
	err := os.Mkdir(dname, 0644)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}

	fname = path.Join(dname, fname)
	fd, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644) // nolint: gosec
	if err != nil {
		return nil, err
	}

	return fd, nil
}

func writeContainerInfo(pod *v1.Pod) error {
	str, ok := pod.Annotations["containerInfo"]
	if !ok {
		return errors.New("Unable to find containerInfo annotation")
	}

	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return errors.Wrap(err, "Unable to base64 decode containerInfo")
	}

	var cInfo titus.ContainerInfo
	err = proto.Unmarshal(data, &cInfo)
	if err != nil {
		return errors.Wrap(err, "Unable to decode containerInfo protobuf")
	}

	out, err := json.MarshalIndent(cInfo, "", " ") // nolint: govet
	if err != nil {
		return errors.Wrap(err, "Unable to marshal containerInfo as JSON")
	}

	fname := path.Join(tt.TitusEnvironmentsDir, pod.Name+".json")

	fd, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644) // nolint: gosec
	if err != nil {
		return err
	}
	defer func() {
		_ = fd.Close()
	}()

	_, err = fd.Write(out)
	return err
}
