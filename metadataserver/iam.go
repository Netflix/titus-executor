package metadataserver

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/metadataserver/types"
	"github.com/aws/aws-sdk-go/service/ec2"

	"sync"

	"github.com/Netflix/titus-executor/metadataserver/metrics"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

type roleAssumptionState struct {
	assumeRoleGenerated time.Time
	assumeRoleOutput    *sts.AssumeRoleOutput
	assumeRoleError     error
}

type iamProxy struct {
	ctx                 context.Context
	roleName            string
	titusTaskInstanceID string
	arn                 arn.ARN
	sts                 *sts.STS

	roleAssumptionState     *roleAssumptionState
	roleAssumptionStateLock *sync.RWMutex
	// This is used to start the role assumer
	roleAssumerOnce *sync.Once

	vpcID              string
	apiProtectPolicy   *string
	apiProtectInfoLock sync.Locker
}

const (
	requestTimeout         = 30 * time.Second
	defaultSessionLifetime = time.Hour
	maxSessionNameLen      = 32
	renewalWindow          = 5 * time.Minute
	awsTimeFormat          = "2006-01-02T15:04:05Z"
)

var (
	invalidSessionNameRegexp = regexp.MustCompile(`[^\w+=,.@-]`)
)

/* This sets up an iam "proxy" and sets up the routes under /{apiVersion}/meta-data/iam/... */
func newIamProxy(ctx context.Context, router *mux.Router, config types.MetadataServerConfiguration) {
	/* This will automatically use *our* metadata proxy to setup the IAM role. */
	parsedArn, err := arn.Parse(config.IAMARN)
	if err != nil {
		log.Fatal("Unable to parse ARN: ", err)
	}

	apiProtectInfoLock := &sync.RWMutex{}

	proxy := &iamProxy{
		ctx:                 ctx,
		titusTaskInstanceID: config.TitusTaskInstanceID,
		arn:                 parsedArn,
		vpcID:               config.VpcID,

		roleAssumerOnce:         &sync.Once{},
		roleAssumptionStateLock: &sync.RWMutex{},

		apiProtectInfoLock: apiProtectInfoLock.RLocker(),
	}
	s := session.Must(session.NewSession())

	if config.Region != "" {
		stsAwsCfg := aws.NewConfig().
			WithRegion(config.Region).
			WithEndpoint(fmt.Sprintf("sts.%s.amazonaws.com", config.Region))
		c := s.ClientConfig(sts.EndpointsID, stsAwsCfg)
		log.WithField("region", config.Region).WithField("endpoint", c.Endpoint).Info("Configure STS client with region")
		proxy.sts = sts.New(s, stsAwsCfg)
	} else {
		proxy.sts = sts.New(s)
	}

	splitRole := strings.Split(proxy.arn.Resource, "/")
	if len(splitRole) != 2 {
		log.Fatal("Unexpected role resource value: ", proxy.arn.Resource)
	}
	proxy.roleName = splitRole[1]

	router.HandleFunc("/info", proxy.info)
	router.HandleFunc("/policy", proxy.policy)
	router.HandleFunc("/security-credentials/", proxy.securityCredentials)
	router.HandleFunc("/security-credentials", redirectSecurityCredentials)

	/* TODO: We should verify that people are actually hitting the right iamProfile, rather
	   than just blindly returning
	*/
	router.HandleFunc("/security-credentials/{iamProfile}", proxy.specificInstanceProfile)

	if config.APIProtectEnabled {
		apiProtectInfoLock.Lock()
		ec2AWSCfg := aws.NewConfig().WithMaxRetries(3)
		if config.Region != "" {
			ec2AWSCfg = ec2AWSCfg.WithRegion(config.Region)
		}

		ec2Client := ec2.New(s, ec2AWSCfg)
		go proxy.getProtectInfo(ec2Client, apiProtectInfoLock, &config.Ipv4Address, config.Ipv6Address)
	}

	if config.Optimistic {
		// No need to block here
		go proxy.startRoleAssumer()
	}
}

// An EC2IAMInfo provides the shape for marshaling
// an IAM info from the metadata API
type ec2IAMInfo struct {
	Code               string
	LastUpdated        string
	InstanceProfileArn string
	InstanceProfileID  string
}

// getProtectInfo is supposed to populate, and unlock proxy.apiProtectInfoLock
func (proxy *iamProxy) getProtectInfo(ec2Client *ec2.EC2, lock *sync.RWMutex, ipv4Address, ipv6Address *net.IP) {
	defer lock.Unlock()

	proxy.apiProtectPolicy = getAPIProtectPolicy(proxy.ctx, ec2Client, proxy.vpcID, ipv4Address, ipv6Address)
	if proxy.apiProtectPolicy == nil {
		log.Warning("API Protect not generated, failing open")
	} else {
		log.WithField("policy", proxy.apiProtectPolicy).Debug("Generated policy")
	}
}

func (proxy *iamProxy) policy(w http.ResponseWriter, r *http.Request) {
	proxy.apiProtectInfoLock.Lock()
	defer proxy.apiProtectInfoLock.Unlock()

	if proxy.apiProtectPolicy == nil {
		w.WriteHeader(404)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err := w.Write([]byte(*proxy.apiProtectPolicy))
	if err != nil {
		log.WithError(err).Error("Unable to write API protect policy")
	}
}

func (proxy *iamProxy) info(w http.ResponseWriter, r *http.Request) {
	/*
		ec2metadata.EC2IAMInfo
	*/
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	roleAssumptionState := proxy.getRoleAssumptionState(ctx)

	if roleAssumptionState == nil {
		http.Error(w, "Role assumption state is nil", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if roleAssumptionState.assumeRoleError == nil {
		ret := ec2IAMInfo{
			Code:               "Success",
			LastUpdated:        roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
			InstanceProfileArn: proxy.arn.String(),
			InstanceProfileID:  *roleAssumptionState.assumeRoleOutput.AssumedRoleUser.AssumedRoleId,
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			log.Warning("Unable to write response: ", err)
		}
		return
	}
	/* See: http://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html */
	if aerr, ok := roleAssumptionState.assumeRoleError.(awserr.Error); ok {
		switch aerr.Code() {
		case "AuthFailure":
			w.WriteHeader(http.StatusForbidden)
		case "UnauthorizedOperation":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		ret := ec2IAMInfo{
			Code:               aerr.Code(),
			LastUpdated:        roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
			InstanceProfileArn: proxy.arn.String(),
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			log.Warning("Unable to write response: ", err)
		}
		return
	}

	w.WriteHeader(http.StatusServiceUnavailable)

	ret := ec2IAMInfo{
		Code:               "ValidationError",
		LastUpdated:        roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
		InstanceProfileArn: proxy.arn.String(),
	}
	if err := json.NewEncoder(w).Encode(ret); err != nil {
		log.Warning("Unable to write response: ", err)
	}
}

func (proxy *iamProxy) securityCredentials(w http.ResponseWriter, r *http.Request) {
	/*
		Just a list, like:
		$ curl 169.254.169.254/latest/meta-data/iam/security-credentials/
		TitusInstanceProfile
	*/
	if _, err := fmt.Fprintf(w, "%s", proxy.roleName); err != nil {
		log.Error("Unable to write output: ", err)
	}
}

// A ec2RoleCredRespBody provides the shape for marshaling credential
// request responses.
// Borrowed from: github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds/ec2_role_provider.go
type ec2RoleCredRespBody struct {
	// Success State
	Expiration      string `json:",omitempty"`
	AccessKeyID     string `json:"AccessKeyId,omitempty"`
	SecretAccessKey string `json:",omitempty"`
	Token           string `json:",omitempty"`
	Type            string `json:",omitempty"`
	LastUpdated     string

	// Error state
	Code    string
	Message string `json:",omitempty"`
}

func (proxy *iamProxy) specificInstanceProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	roleAssumptionState := proxy.getRoleAssumptionState(ctx)

	if roleAssumptionState == nil {
		http.Error(w, "Role assumption state is nil", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if roleAssumptionState.assumeRoleError == nil {
		ret := ec2RoleCredRespBody{
			Expiration:      roleAssumptionState.assumeRoleOutput.Credentials.Expiration.UTC().Format(awsTimeFormat),
			AccessKeyID:     *roleAssumptionState.assumeRoleOutput.Credentials.AccessKeyId,
			SecretAccessKey: *roleAssumptionState.assumeRoleOutput.Credentials.SecretAccessKey,
			Token:           *roleAssumptionState.assumeRoleOutput.Credentials.SessionToken,
			LastUpdated:     roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
			Code:            "Success",
			Type:            "AWS-HMAC",
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			log.Warning("Unable to write response: ", err)
		}
		return
	}

	if aerr, ok := roleAssumptionState.assumeRoleError.(awserr.Error); ok {
		switch aerr.Code() {
		case "AuthFailure":
			w.WriteHeader(http.StatusForbidden)
		case "UnauthorizedOperation":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		ret := ec2RoleCredRespBody{
			Code:        aerr.Code(),
			LastUpdated: roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
			Message:     aerr.Message(),
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			log.Warning("Unable to write response: ", err)
		}
		return
	}

	w.WriteHeader(http.StatusServiceUnavailable)

	ret := ec2RoleCredRespBody{
		Code:        "ValidationError",
		LastUpdated: roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
		Message:     roleAssumptionState.assumeRoleError.Error(),
	}
	if err := json.NewEncoder(w).Encode(ret); err != nil {
		log.Warning("Unable to write response: ", err)
	}

}

func (proxy *iamProxy) startRoleAssumer() {
	proxy.roleAssumerOnce.Do(func() {
		log.Info("Starting role assumer")
		proxy.doAssumeRole(defaultSessionLifetime)
		log.Info("Ran first assume role")

		go proxy.roleAssumer()
	})
}

func (proxy *iamProxy) roleAssumer() {
	// This is a state machine which will wait until we're in a window of being < 5 minutes until our assumerole window is up,
	// and when we hit that, it will keep trying to assume role  every minute until succcessful
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		// Every second, we need to see if we need to do the assumerole dance.
		proxy.maybeAssumeRole(defaultSessionLifetime)
		// Return a number somewhere between 1 and 15 seconds.
		time.Sleep(time.Second * time.Duration(r.Intn(14)+1))
	}
}

func (proxy *iamProxy) maybeAssumeRole(sessionLifetime time.Duration) {
	// The item the pointer points to is immutable.
	// we only mutate the pointer
	proxy.roleAssumptionStateLock.RLock()
	currentRoleAssumptionState := proxy.roleAssumptionState
	proxy.roleAssumptionStateLock.RUnlock()

	if currentRoleAssumptionState == nil {
		log.Debug("Renewing credentials for the first time")
		proxy.doAssumeRole(sessionLifetime)
		return
	}

	if currentRoleAssumptionState.assumeRoleError == nil {
		expiration := *currentRoleAssumptionState.assumeRoleOutput.Credentials.Expiration
		lifetimeRemaining := time.Until(expiration)
		if lifetimeRemaining < renewalWindow {
			log.WithField("lifetimeRemaining", lifetimeRemaining).Info("Renewing credentials")
			proxy.doAssumeRole(sessionLifetime)
		}
	} else if time.Since(currentRoleAssumptionState.assumeRoleGenerated) > 10*time.Second {
		log.WithError(currentRoleAssumptionState.assumeRoleError).Info("Retrying IAM role assumption after failure occured")
		proxy.doAssumeRole(sessionLifetime)
	} else {
		log.Info("Not retrying assume role")
	}
}

func (proxy *iamProxy) doAssumeRole(sessionLifetime time.Duration) {
	ctx, cancel := context.WithTimeout(proxy.ctx, requestTimeout-1*time.Second)
	defer cancel()

	input := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(sessionLifetime.Seconds())),
		RoleArn:         aws.String(proxy.arn.String()),
		RoleSessionName: aws.String(generateSessionName(proxy.titusTaskInstanceID)),
	}

	// This should be safe because this method should be serialized
	// and in addition this is an rlock, which means multiple reads
	// can be in this critical section

	// the only (primary) problem is that this can block forever, and
	// we're protected by the apiProtectInfoFetchTimeout, but who
	// knows how good that codepath is, so we do some futzing here
	proxy.apiProtectInfoLock.Lock()
	defer proxy.apiProtectInfoLock.Unlock()
	if err := ctx.Err(); err != nil {
		log.WithError(err).Error("Context canceled while waiting for api protect info lock")
	}

	if proxy.apiProtectPolicy != nil {
		input.Policy = proxy.apiProtectPolicy
	}
	log.WithField("assumeRoleInput", input).Debug("Assume role input")

	now := time.Now()
	result, err := proxy.sts.AssumeRoleWithContext(ctx, input)
	metrics.PublishTimer("iam.assumeRoleTime", time.Since(now))
	output := &roleAssumptionState{
		assumeRoleGenerated: time.Now(),
		assumeRoleOutput:    result,
		assumeRoleError:     err,
	}
	if err != nil {
		log.Warning("Failed to assume role: ", err)
	} else {
		log.WithField("AccessKeyId", *result.Credentials.AccessKeyId).Info("Assumed role")
	}
	proxy.roleAssumptionStateLock.Lock()
	defer proxy.roleAssumptionStateLock.Unlock()
	proxy.roleAssumptionState = output
}

func (proxy *iamProxy) getRoleAssumptionState(ctx context.Context) *roleAssumptionState {
	// So this can potentially block for up to the upper bound of the request timeout
	proxy.startRoleAssumer()
	proxy.roleAssumptionStateLock.RLock()
	defer proxy.roleAssumptionStateLock.RUnlock()
	return proxy.roleAssumptionState
}

func generateSessionName(containerID string) string {
	sessionName := fmt.Sprintf("titus-%s", containerID)
	sessionName = invalidSessionNameRegexp.ReplaceAllString(sessionName, "_")
	if len(sessionName) <= maxSessionNameLen {
		return sessionName
	}
	return sessionName[0:maxSessionNameLen]
}

func redirectSecurityCredentials(w http.ResponseWriter, r *http.Request) {
	// This is called if someone hits /latest/meta-data/iam/security-credentials
	// We need to 301 them to /latest/meta-data/iam/security-credentials/
	newURI := r.RequestURI + "/"
	http.Redirect(w, r, newURI, http.StatusMovedPermanently)
}
