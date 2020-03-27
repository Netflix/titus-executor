// +build linux

package cni

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"

	"github.com/containernetworking/cni/pkg/version"

	"github.com/Netflix/titus-executor/utils"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	tt "github.com/Netflix/titus-executor/executor/runtime/types"
	mt "github.com/Netflix/titus-executor/metadataserver/types"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
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
	var k8sArgs utils.K8sArgs
	err := types.LoadArgs(args.Args, &k8sArgs)
	if err != nil {
		return "pod-name", errors.Wrap(err, "Unable to parse CNI k8s args")
	}
	logrus.Debugf("k8s args %#v", k8sArgs)

	return string(k8sArgs.K8S_POD_NAME), nil
}

func getPod(args *skel.CmdArgs) (*v1.Pod, error) {
	var k8sArgs utils.K8sArgs
	err := types.LoadArgs(args.Args, &k8sArgs)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to parse CNI k8s args")
	}
	logrus.Debugf("k8s args %#v", k8sArgs)

	ctx := context.Background()
	defer ctx.Done()

	return utils.GetPod(ctx, kubeletAPIPodsURL, k8sArgs)
}

func generateTokenKeySaltIfRequired(pod *v1.Pod) (string, error) {
	fname := path.Join(tt.TitusEnvironmentsDir, fmt.Sprintf("%s.salt", pod.Name))

	_, err := os.Stat(fname)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", errors.Wrap(err, "Unable to stat "+fname)
		}

		fd, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644) // nolint: gosec
		if err != nil {
			return "", err
		}

		if _, err = fmt.Fprint(fd, uuid.New().String()); err != nil {
			return "", err
		}

		if err = fd.Close(); err != nil {
			return "", err
		}
	}

	data, err := ioutil.ReadFile(fname)
	return string(data), err
}

func extractEnv(prev *current.Result, pod *v1.Pod) (map[string]string, error) {
	env := map[string]string{}

	env["LISTEN_PORT"] = "80"

	env["PEER_NAMESPACE"] = getPeerNsPath(pod.Name)
	env["EC2_REGION"] = os.Getenv("EC2_REGION")

	for _, ip := range prev.IPs {
		switch ip.Version {
		case "4":
			env["EC2_LOCAL_IPV4"] = ip.Address.String()
		case "6":
			env["EC2_IPV6S"] = ip.Address.String()
		}
	}

	// pod specific configuration
	env["TITUS_TASK_INSTANCE_ID"] = pod.Name

	// FIXME(manas) make this an annotation in the admission webhook
	env["REQUIRE_TOKEN"] = pod.Annotations[mt.RequireTokenAnnotation]
	salt, err := generateTokenKeySaltIfRequired(pod)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to generate required token salt")
	}
	env["TOKEN_KEY_SALT"] = salt

	env["TITUS_IAM_ROLE"] = pod.Annotations[mt.IamRoleArnAnnotation]
	env["X_FORWARDED_FOR_BLOCKING_MODE"] = pod.Annotations[mt.XForwardedForBlockingModeAnnotation]

	// FIXME(manas) extract this annotation in the admission webhook
	env[mt.TitusMetatronVariableName] = pod.Annotations[mt.MetatronEnabledAnnotation]

	// TODO(manas) remove this from metadata proxy
	env["TITUS_OPTIMISTIC_IAM"] = "true"
	env["TITUS_API_PROTECT_ENABLED"] = "false"
	env["EC2_VPC_ID"] = "vpc-removeapiprotect" // only used by api-protect

	env["IAM_STATE_DIR"] = "/run/titus-metadata-service"

	return env, nil
}

func writeEnvFile(pod *v1.Pod, env map[string]string) error {
	dname := path.Join(tt.TitusEnvironmentsDir, pod.Name)
	fname := path.Join(dname, "imds-proxy.env")

	err := os.Mkdir(dname, 0644)
	if err != nil && !os.IsExist(err) {
		return err
	}

	fd, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644) // nolint: gosec
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
