package pod

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	multierror "github.com/hashicorp/go-multierror"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const (
	AnnotationKeyInstanceType = "node.titus.netflix.com/itype"
	AnnotationKeyRegion       = "node.titus.netflix.com/region"
	AnnotationKeyStack        = "node.titus.netflix.com/stack"
	AnnotationKeyAZ           = "failure-domain.beta.kubernetes.io/zone"

	// Pod Networking
	AnnotationKeyEgressBandwidth  = "kubernetes.io/egress-bandwidth"
	AnnotationKeyIngressBandwidth = "kubernetes.io/ingress-bandwidth"

	// Pod ENI
	AnnotationKeyIPv4Address      = "network.netflix.com/address-ipv4"
	AnnotationKeyIPv4PrefixLength = "network.netflix.com/prefixlen-ipv4"
	AnnotationKeyIPv6Address      = "network.netflix.com/address-ipv6"
	AnnotationKeyIPv6PrefixLength = "network.netflix.com/prefixlen-ipv6"

	AnnotationKeyBranchEniID     = "network.netflix.com/branch-eni-id"
	AnnotationKeyBranchEniMac    = "network.netflix.com/branch-eni-mac"
	AnnotationKeyBranchEniVpcID  = "network.netflix.com/branch-eni-vpc"
	AnnotationKeyBranchEniSubnet = "network.netflix.com/branch-eni-subnet"

	AnnotationKeyTrunkEniID    = "network.netflix.com/trunk-eni-id"
	AnnotationKeyTrunkEniMac   = "network.netflix.com/trunk-eni-mac"
	AnnotationKeyTrunkEniVpcID = "network.netflix.com/trunk-eni-vpc"

	AnnotationKeyVlanID        = "network.netflix.com/vlan-id"
	AnnotationKeyAllocationIdx = "network.netflix.com/allocation-idx"

	// Security

	// matches kube2iam
	AnnotationKeyIAMRole              = "iam.amazonaws.com/role"
	AnnotationKeySecurityGroupsLegacy = "network.titus.netflix.com/securityGroups"
	// https://kubernetes.io/docs/tutorials/clusters/apparmor/#securing-a-pod
	AnnotationKeyPrefixAppArmor = "container.apparmor.security.beta.kubernetes.io"

	//
	// v1 pod spec annotations
	//

	// AnnotationKeyPodSchemaVersion is an integer specifying what schema version a pod was created with
	AnnotationKeyPodSchemaVersion = "pod.netflix.com/pod-schema-version"

	// App-specific fields

	AnnotationKeyAppDetail     = "app.netflix.com/detail"
	AnnotationKeyAppName       = "app.netflix.com/name"
	AnnotationKeyAppOwnerEmail = "app.netflix.com/owner-email"
	AnnotationKeyAppSequence   = "app.netflix.com/sequence"
	AnnotationKeyAppStack      = "app.netflix.com/stack"

	// Titus-specific fields

	AnnotationKeyJobAcceptedTimestampMs = "v3.job.titus.netflix.com/accepted-timestamp-ms"
	AnnotationKeyJobID                  = "v3.job.titus.netflix.com/id"
	AnnotationKeyJobType                = "v3.job.titus.netflix.com/type"
	AnnotationKeyJobDescriptor          = "v3.job.titus.netflix.com/descriptor"
	// AnnotationKeyPodTitusContainerInfo - to be removed once VK supports the full pod spec
	AnnotationKeyPodTitusContainerInfo = "pod.titus.netflix.com/container-info"

	// networking - used by the Titus CNI

	AnnotationKeySubnetsLegacy             = "network.titus.netflix.com/subnets"
	AnnotationKeyAccountIDLegacy           = "network.titus.netflix.com/accountId"
	AnnotationKeyNetworkAccountID          = "network.netflix.com/account-id"
	AnnotationKeyNetworkBurstingEnabled    = "network.netflix.com/network-bursting-enabled"
	AnnotationKeyNetworkAssignIPv6Address  = "network.netflix.com/assign-ipv6-address"
	AnnotationKeyNetworkElasticIPPool      = "network.netflix.com/elastic-ip-pool"
	AnnotationKeyNetworkElasticIPs         = "network.netflix.com/elastic-ips"
	AnnotationKeyNetworkIMDSRequireToken   = "network.netflix.com/imds-require-token"
	AnnotationKeyNetworkJumboFramesEnabled = "network.netflix.com/jumbo-frames-enabled"
	AnnotationKeyNetworkSecurityGroups     = "network.netflix.com/security-groups"
	AnnotationKeyNetworkSubnetIDs          = "network.netflix.com/subnet-ids"
	// TODO: deprecate this in favor of using the UUID annotation below
	AnnotationKeyNetworkStaticIPAllocationUUID = "network.netflix.com/static-ip-allocation-uuid"

	// security

	AnnotationKeySecurityAppMetadata    = "security.netflix.com/app-metadata"
	AnnotationKeySecurityAppMetadataSig = "security.netflix.com/app-metadata-sig"

	// opportunistic resources (see control-plane and scheduler code)

	// AnnotationKeyOpportunisticCPU - assigned opportunistic CPUs
	AnnotationKeyOpportunisticCPU = "opportunistic.scheduler.titus.netflix.com/cpu"
	// AnnotationKeyOpportunisticResourceID - name of the opportunistic resource CRD used during scheduling
	AnnotationKeyOpportunisticResourceID = "opportunistic.scheduler.titus.netflix.com/id"

	// AnnotationKeyPredictionRuntime - predicted runtime (Go’s time.Duration format)
	AnnotationKeyPredictionRuntime = "predictions.scheduler.titus.netflix.com/runtime"
	// AnnotationKeyPredictionConfidence - confidence (percentile) of the prediction picked above
	AnnotationKeyPredictionConfidence = "predictions.scheduler.titus.netflix.com/confidence"
	// AnnotationKeyPredictionModelID - model uuid used for the runtime prediction picked above
	AnnotationKeyPredictionModelID = "predictions.scheduler.titus.netflix.com/model-id"
	// AnnotationKeyPredictionModelVersion - version of the model used for the prediction above
	AnnotationKeyPredictionModelVersion = "predictions.scheduler.titus.netflix.com/version"

	// AnnotationKeyPredictionABTestCell - cell allocation for prediction AB tests
	AnnotationKeyPredictionABTestCell = "predictions.scheduler.titus.netflix.com/ab-test"
	// AnnotationKeyPredictionPredictionAvailable - array of predictions available during job admission
	AnnotationKeyPredictionPredictionAvailable = "predictions.scheduler.titus.netflix.com/available"
	// AnnotationKeyPredictionSelectorInfo - metadata from the prediction selection algorithm
	AnnotationKeyPredictionSelectorInfo = "predictions.scheduler.titus.netflix.com/selector-info"

	// pod features

	AnnotationKeyPodCPUBurstingEnabled      = "pod.netflix.com/cpu-bursting-enabled"
	AnnotationKeyPodKvmEnabled              = "pod.netflix.com/kvm-enabled"
	AnnotationKeyPodFuseEnabled             = "pod.netflix.com/fuse-enabled"
	AnnotationKeyPodHostnameStyle           = "pod.netflix.com/hostname-style"
	AnnotationKeyPodOomScoreAdj             = "pod.netflix.com/oom-score-adj"
	AnnotationKeyPodSchedPolicy             = "pod.netflix.com/sched-policy"
	AnnotationKeyPodSeccompAgentNetEnabled  = "pod.netflix.com/seccomp-agent-net-enabled"
	AnnotationKeyPodSeccompAgentPerfEnabled = "pod.netflix.com/seccomp-agent-perf-enabled"

	// logging config

	AnnotationKeyLogKeepLocalFile       = "log.netflix.com/keep-local-file-after-upload"
	AnnotationKeyLogS3BucketName        = "log.netflix.com/s3-bucket-name"
	AnnotationKeyLogS3PathPrefix        = "log.netflix.com/s3-path-prefix"
	AnnotationKeyLogS3WriterIAMRole     = "log.netflix.com/s3-writer-iam-role"
	AnnotationKeyLogStdioCheckInterval  = "log.netflix.com/stdio-check-interval"
	AnnotationKeyLogUploadThresholdTime = "log.netflix.com/upload-threshold-time"
	AnnotationKeyLogUploadCheckInterval = "log.netflix.com/upload-check-interval"
	AnnotationKeyLogUploadRegexp        = "log.netflix.com/upload-regexp"

	// service configuration

	AnnotationKeyServiceServiceMeshEnabled = "service.netflix.com/service-mesh.enabled"
)

func parseAnnotations(pod *corev1.Pod, pConf *Config) error {
	annotations := pod.GetAnnotations()
	userCtr := GetUserContainer(pod)

	boolAnnotations := []struct {
		key   string
		field **bool
	}{
		{
			key:   AnnotationKeyLogKeepLocalFile,
			field: &pConf.LogKeepLocalFile,
		},
		{
			key:   AnnotationKeyNetworkAssignIPv6Address,
			field: &pConf.AssignIPv6Address,
		},
		{
			key:   AnnotationKeyNetworkBurstingEnabled,
			field: &pConf.NetworkBurstingEnabled,
		},
		{
			key:   AnnotationKeyNetworkJumboFramesEnabled,
			field: &pConf.JumboFramesEnabled,
		},
		{
			key:   AnnotationKeyPodCPUBurstingEnabled,
			field: &pConf.CPUBurstingEnabled,
		},
		{
			key:   AnnotationKeyPodFuseEnabled,
			field: &pConf.FuseEnabled,
		},
		{
			key:   AnnotationKeyPodKvmEnabled,
			field: &pConf.KvmEnabled,
		},
		{
			key:   AnnotationKeyPodSeccompAgentNetEnabled,
			field: &pConf.SeccompAgentNetEnabled,
		},
		{
			key:   AnnotationKeyPodSeccompAgentPerfEnabled,
			field: &pConf.SeccompAgentPerfEnabled,
		},
		{
			key:   AnnotationKeyServiceServiceMeshEnabled,
			field: &pConf.ServiceMeshEnabled,
		},
	}

	durationAnnotations := []struct {
		key   string
		field **time.Duration
	}{
		{
			key:   AnnotationKeyLogStdioCheckInterval,
			field: &pConf.LogStdioCheckInterval,
		},
		{
			key:   AnnotationKeyLogUploadCheckInterval,
			field: &pConf.LogUploadCheckInterval,
		},
		{
			key:   AnnotationKeyLogUploadThresholdTime,
			field: &pConf.LogUploadThresholdTime,
		},
	}

	resourceAnnotations := []struct {
		key   string
		field **resource.Quantity
	}{
		{
			key:   AnnotationKeyEgressBandwidth,
			field: &pConf.EgressBandwidth,
		},
		{
			key:   AnnotationKeyIngressBandwidth,
			field: &pConf.IngressBandwidth,
		},
	}

	stringAnnotations := []struct {
		key   string
		field **string
	}{
		{
			key:   AnnotationKeyPrefixAppArmor + "/" + userCtr.Name,
			field: &pConf.AppArmorProfile,
		},
		{
			key:   AnnotationKeyAppDetail,
			field: &pConf.AppDetail,
		},
		{
			key:   AnnotationKeyAppName,
			field: &pConf.AppName,
		},
		{
			key:   AnnotationKeyAppOwnerEmail,
			field: &pConf.AppOwnerEmail,
		},
		{
			key:   AnnotationKeyAppSequence,
			field: &pConf.AppSequence,
		},
		{
			key:   AnnotationKeyAppStack,
			field: &pConf.AppStack,
		},
		{
			key:   AnnotationKeyIAMRole,
			field: &pConf.IAMRole,
		},
		{
			key:   AnnotationKeyJobDescriptor,
			field: &pConf.JobDescriptor,
		},
		{
			key:   AnnotationKeyJobID,
			field: &pConf.JobID,
		},
		{
			key:   AnnotationKeyJobType,
			field: &pConf.JobType,
		},
		{
			key:   AnnotationKeyLogS3BucketName,
			field: &pConf.LogS3BucketName,
		},
		{
			key:   AnnotationKeyLogS3PathPrefix,
			field: &pConf.LogS3PathPrefix,
		},
		{
			key:   AnnotationKeyLogS3WriterIAMRole,
			field: &pConf.LogS3WriterIAMRole,
		},
		{
			key:   AnnotationKeyNetworkAccountID,
			field: &pConf.AccountID,
		},
		{
			key:   AnnotationKeyNetworkElasticIPPool,
			field: &pConf.ElasticIPPool,
		},
		{
			key:   AnnotationKeyNetworkElasticIPs,
			field: &pConf.ElasticIPs,
		},
		{
			key:   AnnotationKeyNetworkIMDSRequireToken,
			field: &pConf.IMDSRequireToken,
		},
		{
			key:   AnnotationKeyNetworkStaticIPAllocationUUID,
			field: &pConf.StaticIPAllocationUUID,
		},
		{
			key:   AnnotationKeyNetworkSubnetIDs,
			field: &pConf.SubnetIDs,
		},
		{
			key:   AnnotationKeyPodTitusContainerInfo,
			field: &pConf.ContainerInfo,
		},
		{
			key:   AnnotationKeyPodHostnameStyle,
			field: &pConf.HostnameStyle,
		},
		{
			key:   AnnotationKeyPodSchedPolicy,
			field: &pConf.SchedPolicy,
		},
		{
			key:   AnnotationKeySecurityAppMetadata,
			field: &pConf.AppMetadata,
		},
		{
			key:   AnnotationKeySecurityAppMetadataSig,
			field: &pConf.AppMetadataSig,
		},
	}
	var err *multierror.Error

	for _, an := range stringAnnotations {
		val, ok := annotations[an.key]
		if ok {
			*an.field = &val
		}
	}

	if hostnameStyle, ok := annotations[AnnotationKeyPodHostnameStyle]; ok {
		if hostnameStyle != "ec2" && hostnameStyle != "" {
			err = multierror.Append(err, fmt.Errorf("annotation is not a valid hostname style: %s", AnnotationKeyPodHostnameStyle))
		}
	}

	for _, an := range boolAnnotations {
		val, ok := annotations[an.key]
		if ok {
			boolVal, pErr := strconv.ParseBool(val)
			if pErr == nil {
				*an.field = &boolVal
			} else {
				err = multierror.Append(err, fmt.Errorf("annotation is not a valid boolean value: %s", an.key))
			}
		}
	}

	val, ok := annotations[AnnotationKeyPodSchemaVersion]
	if ok {
		parsedVal, pErr := strconv.ParseUint(val, 10, 32)
		if pErr == nil {
			parsedUint32 := uint32(parsedVal)
			pConf.PodSchemaVersion = &parsedUint32
		} else {
			err = multierror.Append(err, fmt.Errorf("annotation is not a valid uint32 value: %s", AnnotationKeyPodSchemaVersion))
		}
	}

	val, ok = annotations[AnnotationKeyJobAcceptedTimestampMs]
	if ok {
		parsedVal, pErr := strconv.ParseUint(val, 10, 64)
		if pErr == nil {
			parsedUint64 := uint64(parsedVal)
			pConf.JobAcceptedTimestampMs = &parsedUint64
		} else {
			err = multierror.Append(err, fmt.Errorf("annotation is not a valid uint64 value: %s", AnnotationKeyJobAcceptedTimestampMs))
		}
	}

	val, ok = annotations[AnnotationKeyPodOomScoreAdj]
	if ok {
		parsedVal, pErr := strconv.ParseInt(val, 10, 32)
		if pErr == nil {
			parsedInt32 := int32(parsedVal)
			pConf.OomScoreAdj = &parsedInt32
		} else {
			err = multierror.Append(err, fmt.Errorf("annotation is not a valid int32 value: %s", AnnotationKeyPodOomScoreAdj))
		}
	}

	for _, an := range resourceAnnotations {
		val, ok := annotations[an.key]
		if ok {
			resVal, pErr := resource.ParseQuantity(val)
			if pErr == nil {
				*an.field = &resVal
			} else {
				err = multierror.Append(err, fmt.Errorf("annotation is not a valid resource value: %s", an.key))
			}
		}
	}

	for _, an := range durationAnnotations {
		val, ok := annotations[an.key]
		if ok {
			durVal, pErr := time.ParseDuration(val)
			if pErr == nil {
				*an.field = &durVal
			} else {
				err = multierror.Append(err, fmt.Errorf("annotation is not a valid duration value: %s", an.key))
			}
		}
	}

	if uploadRegexpVal, ok := annotations[AnnotationKeyLogUploadRegexp]; ok {
		uploadRegexp, pErr := regexp.Compile(uploadRegexpVal)
		if pErr == nil {
			pConf.LogUploadRegExp = uploadRegexp
		} else {
			err = multierror.Append(err, fmt.Errorf("annotation is not a valid regexp value: %s: %w", AnnotationKeyLogUploadRegexp, pErr))
		}
	}

	if sgVal, ok := annotations[AnnotationKeyNetworkSecurityGroups]; ok {
		sgsSplit := strings.Split(strings.TrimSpace(sgVal), ",")
		sgIDs := []string{}
		for _, sg := range sgsSplit {
			sgIDs = append(sgIDs, strings.TrimSpace(sg))
		}
		pConf.SecurityGroupIDs = &sgIDs
	}

	if pConf.SchedPolicy != nil && *pConf.SchedPolicy != "batch" && *pConf.SchedPolicy != "idle" {
		err = multierror.Append(err, fmt.Errorf("annotation is not a valid scheduler policy: %s", AnnotationKeyPodSchedPolicy))
	}

	return err.ErrorOrNil()
}

// PodSchemaVersion returns the pod schema version used to create a pod.
// If unset, returns 0
func PodSchemaVersion(pod *corev1.Pod) (uint32, error) {
	defaultVal := uint32(0)
	val, ok := pod.GetAnnotations()[AnnotationKeyPodSchemaVersion]
	if !ok {
		return defaultVal, nil
	}

	parsedVal, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return defaultVal, fmt.Errorf("annotation is not a valid uint32 value: %s", AnnotationKeyPodSchemaVersion)
	}

	return uint32(parsedVal), nil
}
