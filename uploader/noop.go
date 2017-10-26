package uploader

import (
	"io"
)

// NoopUploader is an uploader to be used when testing
type NoopUploader struct{}

// NewNoopUploader creates a new instance of a NoopUploader
func NewNoopUploader(config map[string]string) (Uploader, error) {
	u := new(NoopUploader)
	return u, nil
}

// Upload does nothing (i.e., noop)
func (u *NoopUploader) Upload(local, remote, contentType string) error {
	return nil
}

// UploadFile does nothing (i.e., noop)
func (u *NoopUploader) UploadFile(local io.Reader, remote, contentType string) error {
	return nil
}

// UploadPartOfFile does nothing (i.e., noop)
func (u *NoopUploader) UploadPartOfFile(local io.ReadSeeker, start, length int64, remote, contentType string) error {
	return nil
}
