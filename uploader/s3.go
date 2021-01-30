package uploader

import (
	"errors"
	"os"
	"path"
	"path/filepath"

	"github.com/Netflix/titus-executor/metadataserver"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"

	"io"

	"context"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"
)

const (
	defaultS3ContentType = "text/plain"
	defaultS3ACL         = s3.ObjectCannedACLBucketOwnerFullControl
	defaultS3PartSize    = 64 * 1024 * 1024 // 64MB per part
)

// S3Backend uploads logs to S3
type S3Backend struct {
	log        log.FieldLogger
	bucketName string
	pathPrefix string
	s3Uploader *s3manager.Uploader
	metrics    metrics.Reporter
}

// NewS3Backend creates a new instance of an S3 manager which uploads to the specified location.
func NewS3Backend(m metrics.Reporter, bucket, prefix, taskRole, taskID, writerRole string, useDefaultRole bool) (Backend, error) {
	region, err := getEC2Region()
	if err != nil {
		panic(err)
	}

	var session *session.Session

	e := log.WithFields(log.Fields{
		"s3_bucket": bucket,
		"s3_prefix": prefix,
	})
	if len(writerRole) > 0 {
		e.WithField("s3_role", writerRole).Info("uploading using writer role")
		session, err = getCustomSession(region, writerRole, taskID)
	} else if useDefaultRole {
		e.Info("uploading using instance profile")
		session, err = getDefaultSession(region)
	} else {
		e.WithField("s3_role", taskRole).Info("uploading using task role")
		session, err = getCustomSession(region, taskRole, taskID)
	}
	if err != nil {
		return nil, err
	}

	return NewS3BackendWithSession(session, m, bucket, prefix), nil
}

// NewS3BackendWithSession creates a new instance of an S3 manager to upload to a given location given a configured session.
func NewS3BackendWithSession(s *session.Session, m metrics.Reporter, bucket, prefix string) Backend {
	s3Uploader := s3manager.NewUploader(s, func(u *s3manager.Uploader) {
		u.PartSize = defaultS3PartSize
	})

	return &S3Backend{
		log:        log.StandardLogger(),
		bucketName: bucket,
		pathPrefix: prefix,
		metrics:    m,
		s3Uploader: s3Uploader,
	}
}

func getDefaultSession(region string) (*session.Session, error) {
	return session.NewSession(&aws.Config{
		Logger: newLogAdapter(),
		Region: &region,
	})
}

func getCustomSession(region, iamRoleArn, taskID string) (*session.Session, error) {
	roleSess, err := session.NewSession(&aws.Config{
		Logger: newLogAdapter(),
		Region: &region,
	})
	if err != nil {
		return nil, err
	}

	cred := stscreds.NewCredentials(roleSess, iamRoleArn, func(p *stscreds.AssumeRoleProvider) {
		// This session key is also used by the iam proxy system service.
		p.RoleSessionName = metadataserver.GenerateSessionName(taskID)
	})

	return session.NewSession(&aws.Config{
		Logger:      newLogAdapter(),
		Region:      &region,
		Credentials: cred,
	})
}

func getEC2Region() (string, error) {
	if region := os.Getenv("EC2_REGION"); region != "" {
		return region, nil
	}

	sess := session.Must(session.NewSession())
	ec2metadatasvc := ec2metadata.New(sess)
	if !ec2metadatasvc.Available() {
		return "", errors.New("Unable to determine EC2 Region, and EC2 metadata service unavailable")
	}
	return ec2metadatasvc.Region()
}

func (u *S3Backend) Upload(ctx context.Context, local string, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	u.log.Printf("Attempting to upload file from %s to %s", local, path.Join(u.bucketName, remote))

	// warning: Potential file inclusion via variable,MEDIUM,HIGH (gosec)
	f, err := os.Open(local) // nolint: gosec
	if err != nil {
		return err
	}
	contentType := ctypeFunc(local)
	if contentType == "" {
		contentType = defaultS3ContentType
	}
	defer func() {
		if err = f.Close(); err != nil {
			u.log.Printf("Failed to close %s: %s", f.Name(), err)
		}
	}()

	return u.uploadFile(ctx, f, remote, contentType)
}

// countingReader is a wrapper of io.Reader to count number of bytes read
type countingReader struct {
	reader    io.Reader
	bytesRead int
}

// Read aggregates number of bytes read
func (r *countingReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if err == nil {
		r.bytesRead += n
	}
	return
}

// UploadFile writes a single file only to S3!
func (u *S3Backend) uploadFile(ctx context.Context, local io.Reader, remote string, contentType string) error {
	if contentType == "" {
		contentType = defaultS3ContentType
	}

	var contentEncoding *string
	if contentType == "text/plain" {
		// On plain text files (default encoding), without setting this, it will be
		// unset, leaving it up to the browser, which means it will be ISO-8859-1 !
		// This can be confusing for users, so this gives us a better default.
		contentEncoding = aws.String("utf-8")
	}

	// wrap input io.Reader with a counting reader
	reader := &countingReader{reader: local}

	result, err := u.s3Uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		ACL:             aws.String(defaultS3ACL),
		ContentType:     aws.String(contentType),
		ContentEncoding: contentEncoding,
		Bucket:          aws.String(u.bucketName),
		Key:             aws.String(filepath.Join(u.pathPrefix, remote)),
		Body:            reader,
	})
	if err != nil {
		return err
	}

	// TITUS-895 emit byes uploaded metrics.  tags = null to get default tags from the wrapped metrics Reporter (see Runner)
	u.metrics.Counter("titus.executor.S3Backend.successfullyUploadedBytes", reader.bytesRead, nil)
	u.log.WithField("local", local).WithField("remote", result.Location).Info("successfully uploaded")

	return nil
}

// UploadPartOfFile copies a single file only. It doesn't preserve the cursor location in the file.
func (u *S3Backend) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	u.log.Printf("Attempting to upload part of file (%d,%d) to %s", start, length, path.Join(u.bucketName, remote))
	if _, err := local.Seek(start, io.SeekStart); err != nil {
		return err
	}
	if contentType == "" {
		contentType = defaultS3ContentType
	}
	limitLocal := io.LimitReader(local, length)
	return u.uploadFile(ctx, limitLocal, remote, contentType)
}

type logAdapter struct {
	log log.StdLogger
}

func newLogAdapter() *logAdapter {
	return &logAdapter{log.StandardLogger()}
}
func (a *logAdapter) Log(args ...interface{}) {
	a.log.Print(args...)
}
