package uploader

import (
	"context"
	"io"
)

// NoopUploader is an uploader to be used when testing
type NoopUploader struct{}

// NewNoopUploader creates a new instance of a NoopUploader
func NewNoopUploader() Uploader {
	u := new(NoopUploader)
	return u
}

// Upload does nothing (i.e., noop)
func (u *NoopUploader) Upload(ctx context.Context, local, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	return ctx.Err()
}

// UploadPartOfFile does nothing (i.e., noop)
func (u *NoopUploader) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	return ctx.Err()
}
