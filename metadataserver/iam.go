package metadataserver

import (
	"net/http"

	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

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
	awsSession          *session.Session
	arn                 arn.ARN
	sts                 *sts.STS

	roleAssumptionInitializationChan chan struct{}
	startRoleAssumerOnce             sync.Once
	roleAcccessed                    chan struct{}
	roleAssumptionStateLock          sync.RWMutex
	roleAssumptionState              *roleAssumptionState
}

const (
	initializationWait = 30 * time.Second
	sessionLifetime    = time.Hour
	maxSessionNameLen  = 32
	renewalWindow      = 5 * time.Minute
	awsTimeFormat      = "2006-01-02T15:04:05Z"
)

var (
	invalidSessionNameRegexp = regexp.MustCompile(`[^\w+=,.@-]`)
)

/* This sets up an iam "proxy" and sets up the routes under /{apiVersion}/meta-data/iam/... */
func newIamProxy(ctx context.Context, router *mux.Router, iamArn, titusTaskInstanceID string) {
	/* This will automatically use *our* metadata proxy to setup the IAM role. */
	arn, err := arn.Parse(iamArn)
	if err != nil {
		log.Fatal("Unable to parse ARN: ", err)
	}

	s := session.Must(session.NewSession())
	proxy := &iamProxy{
		ctx:                 ctx,
		titusTaskInstanceID: titusTaskInstanceID,
		awsSession:          s,
		arn:                 arn,
		sts:                 sts.New(s),
		// This is intentionally >0, so it doesn't explicitly block, allowing the first actor which hits the endpoint
		// to progress and run startRoleAssumer(),
		// And so that during the refresh window,
		roleAcccessed:                    make(chan struct{}, 1000),
		roleAssumptionInitializationChan: make(chan struct{}),
	}
	splitRole := strings.Split(proxy.arn.Resource, "/")
	if len(splitRole) != 2 {
		log.Fatal("Unexpected role resource value: ", proxy.arn.Resource)
	}
	proxy.roleName = splitRole[1]

	router.HandleFunc("/info", proxy.info)
	router.HandleFunc("/security-credentials/", proxy.securityCredentials)
	/* TODO: We should verify that people are actually hitting the right iamProfile, rather
	   than just blindly returning
	*/
	router.HandleFunc("/security-credentials/{iamProfile}", proxy.specificInstanceProfile)
}

// An EC2IAMInfo provides the shape for marshaling
// an IAM info from the metadata API
type ec2IAMInfo struct {
	Code               string
	LastUpdated        string
	InstanceProfileArn string
	InstanceProfileID  string
}

func (proxy *iamProxy) info(w http.ResponseWriter, r *http.Request) {
	/*
		ec2metadata.EC2IAMInfo
	*/
	proxy.roleAcccessed <- struct{}{}
	proxy.startRoleAssumer()
	proxy.roleAssumptionStateLock.RLock()
	defer proxy.roleAssumptionStateLock.RUnlock()
	if proxy.roleAssumptionState == nil {
		http.Error(w, "Role assumption state is nil", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if proxy.roleAssumptionState.assumeRoleError == nil {
		ret := ec2IAMInfo{
			Code:               "Success",
			LastUpdated:        proxy.roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
			InstanceProfileArn: proxy.arn.String(),
			InstanceProfileID:  *proxy.roleAssumptionState.assumeRoleOutput.AssumedRoleUser.AssumedRoleId,
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			log.Warning("Unable to write response: ", err)
		}
		return
	}
	/* See: http://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html */
	if aerr, ok := proxy.roleAssumptionState.assumeRoleError.(awserr.Error); ok {
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
			LastUpdated:        proxy.roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
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
		LastUpdated:        proxy.roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
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
	fmt.Fprintf(w, "%s", proxy.roleName)
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
	proxy.roleAcccessed <- struct{}{}
	proxy.startRoleAssumer()
	proxy.roleAssumptionStateLock.RLock()
	defer proxy.roleAssumptionStateLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if proxy.roleAssumptionState.assumeRoleError == nil {
		ret := ec2RoleCredRespBody{
			Expiration:      proxy.roleAssumptionState.assumeRoleOutput.Credentials.Expiration.UTC().Format(awsTimeFormat),
			AccessKeyID:     *proxy.roleAssumptionState.assumeRoleOutput.Credentials.AccessKeyId,
			SecretAccessKey: *proxy.roleAssumptionState.assumeRoleOutput.Credentials.SecretAccessKey,
			Token:           *proxy.roleAssumptionState.assumeRoleOutput.Credentials.SessionToken,
			LastUpdated:     proxy.roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
			Code:            "Success",
			Type:            "AWS-HMAC",
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			log.Warning("Unable to write response: ", err)
		}
		return
	}

	if aerr, ok := proxy.roleAssumptionState.assumeRoleError.(awserr.Error); ok {
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
			LastUpdated: proxy.roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
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
		LastUpdated: proxy.roleAssumptionState.assumeRoleGenerated.UTC().Format(awsTimeFormat),
		Message:     proxy.roleAssumptionState.assumeRoleError.Error(),
	}
	if err := json.NewEncoder(w).Encode(ret); err != nil {
		log.Warning("Unable to write response: ", err)
	}

}

func (proxy *iamProxy) startRoleAssumer() {
	proxy.startRoleAssumerOnce.Do(func() {
		go proxy.roleAssumer()
	})
	<-proxy.roleAssumptionInitializationChan

}

func (proxy *iamProxy) roleAssumer() {
	initialized := make(chan struct{})
	go func() {
		select {
		case <-initialized:
		case <-time.After(initializationWait):
			log.Warning("Initialization timeout reached for IAM role assumer")
		}
		close(proxy.roleAssumptionInitializationChan)
	}()
	// Do this the first time
	proxy.doAssumeRole()
	close(initialized)
	for range proxy.roleAcccessed {
		proxy.maybeAssumeRole()
	}
}

func (proxy *iamProxy) maybeAssumeRole() {
	// proxy.roleAssumptionState is set when we're in this loop
	if proxy.roleAssumptionState.assumeRoleError == nil {
		expiration := *proxy.roleAssumptionState.assumeRoleOutput.Credentials.Expiration
		if time.Since(expiration) > -1*renewalWindow {
			log.Debug("Renewing credentials")
			proxy.doAssumeRole()
		}
	} else if time.Since(proxy.roleAssumptionState.assumeRoleGenerated) > time.Minute {
		log.Info("Retrying IAM role assumption after failure occured, due to: ", proxy.roleAssumptionState.assumeRoleError)
		proxy.doAssumeRole()
	} else {
		log.Info("Not retrying assume role")
	}
}

func (proxy *iamProxy) doAssumeRole() {
	ctx, cancel := context.WithTimeout(proxy.ctx, initializationWait/2)
	defer cancel()

	input := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(sessionLifetime.Seconds())),
		RoleArn:         aws.String(proxy.arn.String()),
		RoleSessionName: aws.String(generateSessionName(proxy.titusTaskInstanceID)),
	}
	result, err := proxy.sts.AssumeRoleWithContext(ctx, input)
	output := &roleAssumptionState{
		assumeRoleGenerated: time.Now(),
		assumeRoleOutput:    result,
		assumeRoleError:     err,
	}
	if err != nil {
		log.Warning("Failed to assume role: ", err)
	}
	// Keep the lock window as short as possible
	proxy.roleAssumptionStateLock.Lock()
	defer proxy.roleAssumptionStateLock.Unlock()
	proxy.roleAssumptionState = output
}

func generateSessionName(containerID string) string {
	sessionName := fmt.Sprintf("titus-%s", containerID)
	return invalidSessionNameRegexp.ReplaceAllString(sessionName, "_")[0:maxSessionNameLen]
}
