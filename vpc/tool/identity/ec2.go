package identity

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Netflix/titus-executor/logger"
	vpcapi "github.com/Netflix/titus-executor/vpc/api"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ErrEC2MetadataServiceUnavailable = errors.New("EC2 metadata service unavailable")
)

type ec2Provider struct{}

func (e *ec2Provider) GetIdentity(ctx context.Context) (*vpcapi.InstanceIdentity, error) {
	newAWSLogger := &awsLogger{logger: logger.G(ctx), oldMessages: list.New()}
	ec2MetadataClient := ec2metadata.New(
		session.Must(
			session.NewSession(
				aws.NewConfig().
					WithMaxRetries(3).
					WithLogger(newAWSLogger).
					WithLogLevel(aws.LogDebugWithRequestErrors | aws.LogDebugWithRequestRetries | aws.LogDebugWithHTTPBody))))

	if !ec2MetadataClient.Available() {
		return nil, ErrEC2MetadataServiceUnavailable
	}

	resp, err := ec2MetadataClient.GetDynamicData("instance-identity/document")
	if err != nil {
		return nil, errors.Wrap(err, "Unable to fetch instance identity document")
	}

	pkcs7, err := ec2MetadataClient.GetDynamicData("instance-identity/pkcs7")
	if err != nil {
		return nil, errors.Wrap(err, "Unable to fetch instance identity signature")
	}

	var doc ec2metadata.EC2InstanceIdentityDocument
	err = json.Unmarshal([]byte(resp), &doc)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot deserialize instance identity document")
	}

	return &vpcapi.InstanceIdentity{
		InstanceIdentityDocument:  resp,
		InstanceIdentitySignature: pkcs7,
		InstanceID:                doc.InstanceID,
		Region:                    doc.Region,
		AccountID:                 doc.AccountID,
		InstanceType:              doc.InstanceType,
	}, err
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
