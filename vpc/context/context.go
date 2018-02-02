package context

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"math/rand"

	"fmt"
	"strings"

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

type awsLogger struct {
	logger *logrus.Entry
}

func (l *awsLogger) Log(args ...interface{}) {
	formattedAWSArg := fmt.Sprint(args...)
	// AWS doesn't have a way to enable error logging without enabling debug logging...
	if strings.Contains(formattedAWSArg, "ERROR") || strings.Contains(formattedAWSArg, "error") {
		l.logger.WithField("origin", "aws").Error(formattedAWSArg)
	}
}

func (ctx *VPCContext) setupEC2() error {
	ec2MetadataClient := ec2metadata.New(session.Must(session.NewSession()))
	if !ec2MetadataClient.Available() {
		return cli.NewExitError("EC2 metadata service unavailable", 1)
	}
	if instanceIDDocument, err := getInstanceIdentityDocument(ec2MetadataClient); err == nil {
		ctx.InstanceType = instanceIDDocument.InstanceType
		ctx.InstanceID = instanceIDDocument.InstanceID

		awsConfig := aws.NewConfig().
			WithMaxRetries(3).
			WithRegion(instanceIDDocument.Region).
			WithLogger(&awsLogger{logger: ctx.Logger}).
			WithLogLevel(aws.LogDebugWithRequestErrors | aws.LogDebugWithRequestRetries)

		if session, err2 := session.NewSession(awsConfig); err2 == nil {
			ctx.AWSSession = session
			ctx.EC2metadataClientWrapper = ec2wrapper.NewEC2MetadataClientWrapper(session, ctx.Logger)
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
