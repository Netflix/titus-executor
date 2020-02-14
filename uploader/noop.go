package uploader

import (
	"context"
	"io"
)

// NoopBackend is an uploader to be used when testing
type NoopBackend struct{}

// NewNoopBackend creates a new instance of a NoopBackend
func NewNoopBackend() Backend {
	u := new(NoopBackend)
	return u
}

// Upload does nothing (i.e., noop)
func (u *NoopBackend) Upload(ctx context.Context, local, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	return ctx.Err()
}

// UploadPartOfFile does nothing (i.e., noop)
func (u *NoopBackend) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	return ctx.Err()
}
