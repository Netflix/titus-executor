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
import "github.com/aws/aws-sdk-go/aws/client"

// StateDir is the name for the state directory flag
const StateDir = "state-dir"

type vpcContext struct {
	context.Context
	*session.Session
	cliContext               *cli.Context
	fsLocker                 *fslocker.FSLocker
	ec2metadataClientWrapper *ec2wrapper.EC2MetadataClientWrapper
	logger                   *logrus.Entry
	instanceType             string
	instanceID               string
	subnetCache              *SubnetCache
}

// VPCContext encapsulates some information that's gleaned at init time
type VPCContext interface {
	context.Context
	client.ConfigProvider
	FSLocker() *fslocker.FSLocker
	//AWSSession() *session.Session
	EC2metadataClientWrapper() *ec2wrapper.EC2MetadataClientWrapper
	Logger() *logrus.Entry
	InstanceType() string
	InstanceID() string
	SubnetCache() *SubnetCache
	WithCancel() (VPCContext, context.CancelFunc)
	WithTimeout(timeout time.Duration) (VPCContext, context.CancelFunc)
	WithField(key string, value interface{}) VPCContext
}

// VPCContextWithCLI has the cli object included with context
type VPCContextWithCLI interface {
	VPCContext
	CLIContext() *cli.Context
}

func newVPCContext(cliContext *cli.Context) (VPCContextWithCLI, error) {
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
	ret := &vpcContext{
		Context:    context.Background(),
		logger:     logrus.NewEntry(logger),
		cliContext: cliContext,
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
	ret.fsLocker = locker

	subnetCachingDirectory := filepath.Join(stateDir, "subnets")
	err = os.MkdirAll(subnetCachingDirectory, 0700)
	if err != nil {
		return nil, err
	}
	ret.subnetCache = newSubnetCache(locker, subnetCachingDirectory)

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

func (ctx *vpcContext) setupEC2() error {
	newAWSLogger := &awsLogger{logger: ctx.logger, oldMessages: list.New()}
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
		ctx.instanceType = instanceIDDocument.InstanceType
		ctx.instanceID = instanceIDDocument.InstanceID

		awsConfig := aws.NewConfig().
			WithMaxRetries(3).
			WithRegion(instanceIDDocument.Region).
			WithLogger(newAWSLogger).
			WithLogLevel(aws.LogDebugWithRequestErrors | aws.LogDebugWithRequestRetries | aws.LogDebugWithHTTPBody)

		if session, err2 := session.NewSession(awsConfig); err2 == nil {
			ctx.Session = session
			ctx.ec2metadataClientWrapper = ec2wrapper.NewEC2MetadataClientWrapper(session, ctx.logger)
		} else {
			return cli.NewMultiError(cli.NewExitError("Unable to create AWS Session", 1), err2)
		}
	} else {
		return cli.NewMultiError(cli.NewExitError("Unable to get instance identity", 1), err)
	}

	return nil
}

// WithCancel returns a copy of context, with cancel
func (ctx *vpcContext) WithCancel() (VPCContext, context.CancelFunc) {
	ret := &vpcContext{}
	*ret = *ctx
	newCtx, cancel := context.WithCancel(ctx.Context)
	ret.Context = newCtx
	return ret, cancel
}

// WithTimeout returns a copy of context, with timeout
func (ctx *vpcContext) WithTimeout(timeout time.Duration) (VPCContext, context.CancelFunc) {
	ret := &vpcContext{}
	*ret = *ctx
	newCtx, cancel := context.WithTimeout(ctx.Context, timeout)
	ret.Context = newCtx
	return ret, cancel
}

// WithField returns a copy of the context, but with this key-value added to the logger
func (ctx *vpcContext) WithField(key string, value interface{}) VPCContext {
	ret := &vpcContext{}
	*ret = *ctx
	ret.logger = ctx.logger.WithField(key, value)
	return ret
}

// WrapFunc should only be used to setup initial context object for command entry
func WrapFunc(internalFunc func(VPCContextWithCLI) error) func(*cli.Context) error {
	return func(cliCtx *cli.Context) error {
		ctx, err := newVPCContext(cliCtx)
		if err != nil {
			return err
		}
		return internalFunc(ctx)
	}
}

func (ctx *vpcContext) FSLocker() *fslocker.FSLocker {
	return ctx.fsLocker
}
func (ctx *vpcContext) AWSSession() *session.Session {
	return ctx.Session
}
func (ctx *vpcContext) EC2metadataClientWrapper() *ec2wrapper.EC2MetadataClientWrapper {
	return ctx.ec2metadataClientWrapper
}
func (ctx *vpcContext) Logger() *logrus.Entry {
	return ctx.logger
}
func (ctx *vpcContext) InstanceType() string {
	return ctx.instanceType
}
func (ctx *vpcContext) InstanceID() string {
	return ctx.instanceID
}
func (ctx *vpcContext) SubnetCache() *SubnetCache {
	return ctx.subnetCache
}

func (ctx *vpcContext) CLIContext() *cli.Context {
	return ctx.cliContext
}
