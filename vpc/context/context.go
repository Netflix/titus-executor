package context

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"math/rand"

	"fmt"
	"strings"

	"container/list"

	"github.com/Netflix/titus-executor/fslocker"
	"github.com/Netflix/titus-executor/vpc/ec2wrapper"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/sirupsen/logrus"
	"github.com/wercker/journalhook"
	"gopkg.in/urfave/cli.v1"
)

// StateDir is the name for the state directory flag
const StateDir = "state-dir"

// VPCContext encapsulates some information that's gleaned at init time
type VPCContext struct {
	context.Context
	CLIContext               *cli.Context
	FSLocker                 *fslocker.FSLocker
	AWSSession               *session.Session
	EC2metadataClientWrapper *ec2wrapper.EC2MetadataClientWrapper
	Logger                   *logrus.Entry
	InstanceType             string
	InstanceID               string
	SubnetCache              *SubnetCache
}

func newVPCContext(cliContext *cli.Context) (*VPCContext, error) {
	logger := logrus.New()
	// Setup log level
	level, err := logrus.ParseLevel(cliContext.GlobalString("log-level"))
	if err != nil {
		return nil, cli.NewMultiError(cli.NewExitError("Invalid log level", 1), err)
	}
	logger.Level = level

	if cliContext.GlobalBoolT("journald") {
		logger.Hooks.Add(&journalhook.JournalHook{})
	} else {
		logger.Info("Disabling journald hook")
	}
	ret := &VPCContext{
		Context:    context.Background(),
		CLIContext: cliContext,
		Logger:     logrus.NewEntry(logger),
	}

	// Setup EC2 client
	err = ret.setupEC2()
	if err != nil {
		logger.Warning("Unable to setup EC2 client: ", err)
		return nil, err
	}

	// Setup state manager:
	stateDir := cliContext.GlobalString(StateDir)
	if stateDir == "" {
		return nil, cli.NewExitError("state directory not specified", 1)
	}

	fslockerDir := filepath.Join(stateDir, "fslocker")
	err = os.MkdirAll(fslockerDir, 0700)
	if err != nil {
		return nil, err
	}

	locker, err := fslocker.NewFSLocker(fslockerDir)
	if err != nil {
		return nil, err
	}
	ret.FSLocker = locker

	subnetCachingDirectory := filepath.Join(stateDir, "subnets")
	err = os.MkdirAll(subnetCachingDirectory, 0700)
	if err != nil {
		return nil, err
	}
	ret.SubnetCache = newSubnetCache(locker, subnetCachingDirectory)

	return ret, nil
}

func getInstanceIdentityDocument(ec2MetadataClient *ec2metadata.EC2Metadata) (ec2metadata.EC2InstanceIdentityDocument, error) {
	var instanceIdentityDocument ec2metadata.EC2InstanceIdentityDocument
	var err error
	for i := 0; i < 10; i++ {
		instanceIdentityDocument, err = ec2MetadataClient.GetInstanceIdentityDocument()
		if err == nil {
			break
		}
		// Sleep a minimum of 10 milliseconds, and up to 50 ms
		jitter := time.Millisecond * time.Duration(rand.Intn(40)+10)
		time.Sleep(jitter)
	}
	return instanceIdentityDocument, err
}

// This isn't thread safe. But that's okay, because we don't use it in a multi-threaded way.
type awsLogger struct {
	logger      *logrus.Entry
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
		l.debugMode = true
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

func (ctx *VPCContext) setupEC2() error {
	newAWSLogger := &awsLogger{logger: ctx.Logger, oldMessages: list.New()}
	ec2MetadataClient := ec2metadata.New(
		session.Must(
			session.NewSession(
				aws.NewConfig().
					WithMaxRetries(3).
					WithLogger(newAWSLogger).
					WithLogLevel(aws.LogDebugWithRequestErrors | aws.LogDebugWithRequestRetries | aws.LogDebugWithHTTPBody))))
	if !ec2MetadataClient.Available() {
		return cli.NewExitError("EC2 metadata service unavailable", 1)
	}
	if instanceIDDocument, err := getInstanceIdentityDocument(ec2MetadataClient); err == nil {
		ctx.InstanceType = instanceIDDocument.InstanceType
		ctx.InstanceID = instanceIDDocument.InstanceID

		awsConfig := aws.NewConfig().
			WithMaxRetries(3).
			WithRegion(instanceIDDocument.Region).
			WithLogger(newAWSLogger).
			WithLogLevel(aws.LogDebugWithRequestErrors | aws.LogDebugWithRequestRetries | aws.LogDebugWithHTTPBody)

		if awsSession, err2 := session.NewSession(awsConfig); err2 == nil {
			ctx.AWSSession = awsSession
			ctx.EC2metadataClientWrapper = ec2wrapper.NewEC2MetadataClientWrapper(awsSession, ctx.Logger)
		} else {
			return cli.NewMultiError(cli.NewExitError("Unable to create AWS Session", 1), err2)
		}
	} else {
		return cli.NewMultiError(cli.NewExitError("Unable to get instance identity", 1), err)
	}

	return nil
}

// WithCancel returns a copy of context, with cancel
func (ctx *VPCContext) WithCancel() (*VPCContext, context.CancelFunc) {
	ret := &VPCContext{}
	*ret = *ctx
	newCtx, cancel := context.WithCancel(ctx.Context)
	ret.Context = newCtx
	return ret, cancel
}

// WithTimeout returns a copy of context, with timeout
func (ctx *VPCContext) WithTimeout(timeout time.Duration) (*VPCContext, context.CancelFunc) {
	ret := &VPCContext{}
	*ret = *ctx
	newCtx, cancel := context.WithTimeout(ctx.Context, timeout)
	ret.Context = newCtx
	return ret, cancel
}

// WithField returns a copy of the context, but with this key-value added to the logger
func (ctx *VPCContext) WithField(key string, value interface{}) *VPCContext {
	ret := &VPCContext{}
	*ret = *ctx
	ret.Logger = ctx.Logger.WithField(key, value)
	return ret
}

// WrapFunc should only be used to setup initial context object for command entry
func WrapFunc(internalFunc func(*VPCContext) error) func(*cli.Context) error {
	return func(cliCtx *cli.Context) error {
		ctx, err := newVPCContext(cliCtx)
		if err != nil {
			return err
		}
		return internalFunc(ctx)
	}
}
