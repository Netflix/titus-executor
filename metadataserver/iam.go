package metadataserver

import (
	"net/http"

	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
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

	roleAcccessed       chan *roleAccessedNotification
	roleAssumptionState atomic.Value
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

type roleAccessedNotification struct {
	processed                 chan struct{}
	overriddenSessionLifetime *time.Duration
}

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
		roleAcccessed: make(chan *roleAccessedNotification),
	}
	// This is to store the type so it just doesn't return nothing on the first load
	proxy.roleAssumptionState.Store((*roleAssumptionState)(nil))

	splitRole := strings.Split(proxy.arn.Resource, "/")
	if len(splitRole) != 2 {
		log.Fatal("Unexpected role resource value: ", proxy.arn.Resource)
	}
	proxy.roleName = splitRole[1]

	router.HandleFunc("/info", proxy.info)
	router.HandleFunc("/security-credentials/", proxy.securityCredentials)
	router.HandleFunc("/security-credentials", redirectSecurityCredentials)

	/* TODO: We should verify that people are actually hitting the right iamProfile, rather
	   than just blindly returning
	*/
	router.HandleFunc("/security-credentials/{iamProfile}", proxy.specificInstanceProfile)
	go proxy.roleAssumer()
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
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	proxy.notifyRoleAccessed(ctx, r)
	roleAssumptionState := proxy.getRoleAssumptionState()

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
	proxy.notifyRoleAccessed(ctx, r)
	roleAssumptionState := proxy.getRoleAssumptionState()

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

func (proxy *iamProxy) notifyRoleAccessed(ctx context.Context, r *http.Request) {
	ran := &roleAccessedNotification{
		processed: make(chan struct{}),
	}
	if val := r.Header.Get("X-Override-Session-Lifetime"); val != "" {
		if dur, err := time.ParseDuration(val); err != nil {
			log.Warning("Unable to parse session override duration: ", err)
		} else {
			ran.overriddenSessionLifetime = &dur
		}
	}
	select {
	case <-ctx.Done():
		log.Warning("Context done, before notify role access message sent: ", ctx.Err())
	case proxy.roleAcccessed <- ran:
	}
	select {
	case <-ctx.Done():
		log.Warning("Context done, before notify role access message processed: ", ctx.Err())
	case <-ran.processed:
	}
}

func (proxy *iamProxy) roleAssumer() {
	for roleAccessed := range proxy.roleAcccessed {
		sessionLifetime := defaultSessionLifetime
		if roleAccessed.overriddenSessionLifetime != nil {
			if *roleAccessed.overriddenSessionLifetime > defaultSessionLifetime {
				log.Warning("User is trying to ask for an extra long session")
			} else {
				sessionLifetime = *roleAccessed.overriddenSessionLifetime
			}
		}
		proxy.maybeAssumeRole(sessionLifetime)
		close(roleAccessed.processed)
	}
}

func (proxy *iamProxy) maybeAssumeRole(sessionLifetime time.Duration) {
	// proxy.roleAssumptionState is set when we're in this loop
	roleAssumptionState := proxy.getRoleAssumptionState()
	if roleAssumptionState == nil {
		log.Debug("Renewing credentials for the first time")
		proxy.doAssumeRole(sessionLifetime)
	} else if roleAssumptionState.assumeRoleError == nil {
		expiration := *roleAssumptionState.assumeRoleOutput.Credentials.Expiration
		if time.Until(expiration) < renewalWindow {
			log.Debug("Renewing credentials")
			proxy.doAssumeRole(sessionLifetime)
		}
	} else if time.Since(roleAssumptionState.assumeRoleGenerated) > time.Minute {
		log.Info("Retrying IAM role assumption after failure occured, due to: ", roleAssumptionState.assumeRoleError)
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
	proxy.roleAssumptionState.Store(output)
}

func (proxy *iamProxy) getRoleAssumptionState() *roleAssumptionState {
	return proxy.roleAssumptionState.Load().(*roleAssumptionState)
}

func generateSessionName(containerID string) string {
	sessionName := fmt.Sprintf("titus-%s", containerID)
	return invalidSessionNameRegexp.ReplaceAllString(sessionName, "_")[0:maxSessionNameLen]
}

func redirectSecurityCredentials(w http.ResponseWriter, r *http.Request) {
	// This is called if someone hits /latest/meta-data/iam/security-credentials
	// We need to 301 them to /latest/meta-data/iam/security-credentials/
	newURI := r.RequestURI + "/"
	http.Redirect(w, r, newURI, http.StatusMovedPermanently)
}
