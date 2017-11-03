package uploader

import (
	"errors"
	"os"
	"path"

	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/sirupsen/logrus"
)

const (
	defaultS3ContentType = "text/plain"
	defaultS3ACL         = s3.ObjectCannedACLBucketOwnerFullControl
	defaultS3PartSize    = 64 * 1024 * 1024 // 64MB per part
)

// S3Uploader uploads logs to S3
type S3Uploader struct {
	log        logrus.FieldLogger
	bucketName string
	s3Uploader *s3manager.Uploader
}

// NewS3Uploader creates a new instance of an S3 uploader
func NewS3Uploader(log logrus.FieldLogger, config map[string]string) (Uploader, error) {
	log.Printf("s3 : init from config: %v", config)

	// verify config
	if config["bucket"] == "" {
		return nil, errors.New("no bucket specified")
	}

	u := &S3Uploader{
		log:        log,
		bucketName: config["bucket"],
	}

	session, err := session.NewSession(&aws.Config{
		Logger: &logAdapter{log},
	})
	if err != nil {
		return nil, err
	}
	u.s3Uploader = s3manager.NewUploader(session, func(u *s3manager.Uploader) {
		u.PartSize = defaultS3PartSize
	})

	return u, nil
}

// Upload writes a single file only to S3!
func (u *S3Uploader) Upload(local string, remote string, contentType string) error {
	u.log.Printf("Attempting to upload file from: %s to: %s", local, path.Join(u.bucketName, remote))

	f, err := os.Open(local)
	if err != nil {
		return err
	}
	defer func() {
		if err = f.Close(); err != nil {
			u.log.Printf("Failed to close %s: %s", f.Name(), err)
		}
	}()

	return u.UploadFile(f, remote, contentType)
}

// UploadFile writes a single file only to S3!
func (u *S3Uploader) UploadFile(local io.Reader, remote string, contentType string) error {
	u.log.Printf("Attempting to upload file from: %s to: %s", local, path.Join(u.bucketName, remote))

	result, err := u.s3Uploader.Upload(&s3manager.UploadInput{
		ACL:         aws.String(defaultS3ACL),
		ContentType: aws.String(defaultS3ContentType),
		Bucket:      aws.String(u.bucketName),
		Key:         aws.String(remote),
		Body:        local,
	})
	if err != nil {
		return err
	}

	u.log.Printf("Successfully uploaded file from: %s to: %s", local, result.Location)

	return nil
}

// UploadPartOfFile copies a single file only. It doesn't preserve the cursor location in the file.
func (u *S3Uploader) UploadPartOfFile(local io.ReadSeeker, start, length int64, remote, contentType string) error {
	if _, err := local.Seek(start, io.SeekStart); err != nil {
		return err
	}
	limitLocal := io.LimitReader(local, length)
	return u.UploadFile(limitLocal, remote, contentType)
}

type logAdapter struct {
	log logrus.StdLogger
}

func (a *logAdapter) Log(args ...interface{}) {
	a.log.Print(args...)
}
