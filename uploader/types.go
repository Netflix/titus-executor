package uploader

import (
	"io"
)

// Uploader is a common interface for a service that can upload log
// files somewhere
type Uploader interface {
	Upload(local, remote string, ctypeFunc ContentTypeInferenceFunction) error
	UploadPartOfFile(local io.ReadSeeker, start, length int64, remote, contentType string) error
}

// ContentTypeInferenceFunction is the callback that can be used to set the mime type of a file at upload time
type ContentTypeInferenceFunction func(filename string) string
