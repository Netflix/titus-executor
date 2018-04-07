package uploader

import (
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
func (u *NoopUploader) Upload(local, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	return nil
}

// UploadPartOfFile does nothing (i.e., noop)
func (u *NoopUploader) UploadPartOfFile(local io.ReadSeeker, start, length int64, remote, contentType string) error {
	return nil
}
