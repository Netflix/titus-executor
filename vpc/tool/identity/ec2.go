package identity

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.opencensus.io/stats"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/google/renameio"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
)

var (
	ErrEC2MetadataServiceUnavailable = errors.New("EC2 metadata service unavailable")
	ErrEC2MetadataFileNotFound       = errors.New("EC2 metadata file was not found")
	ErrPkcsFileNotFound              = errors.New("PKCS file was not found")
)

var (
	getIdentityLatency = stats.Float64("getIdentity.latency", "The time to get an instance's identity", "ns")
	getIdentityCount   = stats.Int64("getIdentity.count", "How many times getIdentity was called", "")
	getIdentitySuccess = stats.Int64("getIdentity.success.count", "How many times getIdentity succeeded", "")
)

const (
	InstanceIdentityFile = "/run/instanceIdentity/doc"
	PkcsFile             = "/run/instanceIdentity/pkcs"
)

type ec2Provider struct{}

func (e *ec2Provider) GetIdentity(ctx context.Context) (*vpcapi.InstanceIdentity, error) {
	var pkcsFile *os.File
	ctx, span := trace.StartSpan(ctx, "GetIdentity")
	defer span.End()
	start := time.Now()
	stats.Record(ctx, getIdentityCount.M(1))

	newAWSLogger := &awsLogger{logger: logger.G(ctx), oldMessages: list.New()}

	// Attempt to read the data off of cache
	instanceIdentityFile, err := os.OpenFile(InstanceIdentityFile, os.O_RDONLY, 0644)
	if err != nil {
		tracehelpers.SetStatus(ErrEC2MetadataFileNotFound, span)
		goto fetchFromImds
	}

	pkcsFile, err = os.OpenFile(PkcsFile, os.O_RDONLY, 0644)
	if err != nil {
		tracehelpers.SetStatus(ErrPkcsFileNotFound, span)
		goto fetchFromImds
	} else {
		defer instanceIdentityFile.Close()
		defer pkcsFile.Close()

		// Read the instance Identity file
		instanceID, err := ioutil.ReadAll(instanceIdentityFile)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			goto fetchFromImds
		}
		var doc ec2metadata.EC2InstanceIdentityDocument
		err = json.Unmarshal(instanceID, &doc)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			goto fetchFromImds
		}

		// Read the pkcs7 file
		pkcs7, err := ioutil.ReadAll(pkcsFile)
		if err != nil {
			tracehelpers.SetStatus(err, span)
			goto fetchFromImds
		}

		return &vpcapi.InstanceIdentity{
			InstanceIdentityDocument:  string(instanceID),
			InstanceIdentitySignature: string(pkcs7),
			InstanceID:                doc.InstanceID,
			Region:                    doc.Region,
			AccountID:                 doc.AccountID,
			InstanceType:              doc.InstanceType,
		}, err
	}
fetchFromImds:
	ec2MetadataClient := ec2metadata.New(
		session.Must(
			session.NewSession(
				aws.NewConfig().
					WithMaxRetries(3).
					WithLogger(newAWSLogger).
					WithLogLevel(aws.LogDebugWithRequestErrors | aws.LogDebugWithRequestRetries | aws.LogDebugWithHTTPBody))))

	if !ec2MetadataClient.Available() {
		tracehelpers.SetStatus(ErrEC2MetadataServiceUnavailable, span)
		return nil, ErrEC2MetadataServiceUnavailable
	}

	resp, err := ec2MetadataClient.GetDynamicData("instance-identity/document")
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, errors.Wrap(err, "Unable to fetch instance identity document")
	}

	pkcs7, err := ec2MetadataClient.GetDynamicData("instance-identity/pkcs7")
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, errors.Wrap(err, "Unable to fetch instance identity signature")
	}

	var doc ec2metadata.EC2InstanceIdentityDocument
	err = json.Unmarshal([]byte(resp), &doc)
	if err != nil {
		tracehelpers.SetStatus(err, span)
		return nil, errors.Wrap(err, "Cannot deserialize instance identity document")
	}

	stats.Record(ctx, getIdentityLatency.M(float64(time.Since(start).Nanoseconds())), getIdentitySuccess.M(1))

	go cacheIdentityFiles(ctx, resp, pkcs7)

	return &vpcapi.InstanceIdentity{
		InstanceIdentityDocument:  resp,
		InstanceIdentitySignature: pkcs7,
		InstanceID:                doc.InstanceID,
		Region:                    doc.Region,
		AccountID:                 doc.AccountID,
		InstanceType:              doc.InstanceType,
	}, err
}

func cacheIdentityFiles(ctx context.Context, resp string, pkcs string) {
	_, span := trace.StartSpan(ctx, "GetIdentity")
	defer span.End()

	if err := os.MkdirAll(filepath.Dir(InstanceIdentityFile), 0755); err != nil {
		tracehelpers.SetStatus(err, span)
		return
	}
	if err := renameio.WriteFile(InstanceIdentityFile, []byte(resp), 0644); err != nil {
		tracehelpers.SetStatus(err, span)
		return
	}
	if err := renameio.WriteFile(PkcsFile, []byte(pkcs), 0644); err != nil {
		tracehelpers.SetStatus(err, span)
		return
	}
}

// This isn't thread safe. But that's okay, because we don't use it in a multi-threaded way.
type awsLogger struct {
	logger      logrus.FieldLogger
	debugMode   bool
	oldMessages *list.List
}

type oldMessage struct {
	entry           *logrus.Entry
	formattedAWSArg string
}

func (l *awsLogger) Log(args ...interface{}) {
	formattedAWSArg := fmt.Sprint(args...)
	// AWS doesn't have a way to enable error logging without enabling debug logging...
	message := l.logger.WithField("origin", "aws").WithField("debugMode", l.debugMode)
	if l.debugMode {
		message.Error(formattedAWSArg)
		return
	}

	if strings.Contains(formattedAWSArg, "EOF") || strings.Contains(formattedAWSArg, "404 - Not Found") {
		// We need to dump all existing logs, and in addition turn our internal log level to debug
		message.Error(formattedAWSArg)
		l.dumpExistingMessages()
		return
	}
	if strings.Contains(formattedAWSArg, "ERROR") || strings.Contains(formattedAWSArg, "error") {
		message.Error(formattedAWSArg)
		return
	}

	msg := &oldMessage{
		entry:           message.WithField("originalTimestamp", time.Now()),
		formattedAWSArg: formattedAWSArg,
	}
	l.oldMessages.PushBack(msg)
}

func (l *awsLogger) dumpExistingMessages() {
	for e := l.oldMessages.Front(); e != nil; e = e.Next() {
		le := e.Value.(*oldMessage)
		le.entry.Error(le.formattedAWSArg)
	}
	// Dump old Messages, reinitialize it to wipe out all messages.
	l.oldMessages = list.New()
}
