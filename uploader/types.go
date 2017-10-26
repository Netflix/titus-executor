package uploader

import (
	"io"
)

// Uploader is a common interface for a service that can upload log
// files somewhere
type Uploader interface {
	Upload(local, remote, contentType string) error
	UploadFile(local io.Reader, remote, contentType string) error
	UploadPartOfFile(local io.ReadSeeker, start, length int64, remote, contentType string) error
}
