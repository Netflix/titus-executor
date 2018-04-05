package uploader

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"io"

	"github.com/Netflix/titus-executor/config"
	log "github.com/sirupsen/logrus"
)

func collectCopyUploaders(cfg *config.Config) []Uploader {
	copyUploaders := []Uploader{}
	for _, uploaderArg := range cfg.CopyUploaders {
		copyUploaders = append(copyUploaders, NewCopyUploader(uploaderArg))
	}

	return copyUploaders
}

func collectS3Uploaders(cfg *config.Config) []Uploader {
	copyUploaders := []Uploader{}
	for _, uploaderArg := range cfg.S3Uploaders {
		copyUploaders = append(copyUploaders, NewS3Uploader(log.StandardLogger(), uploaderArg))
	}

	return copyUploaders
}

func collectNoopUploaders(cfg *config.Config) []Uploader {
	copyUploaders := []Uploader{}
	for range cfg.NoopUploaders {
		copyUploaders = append(copyUploaders, NewNoopUploader())
	}

	return copyUploaders
}

// Uploaders is a slice wrapper that contains all of the
// uploaders to use when tasks complete
type Uploaders struct {
	uploaders []Uploader
}

// NewUploaders creates a new instance of an Uploaders object
func NewUploaders(config *config.Config) (*Uploaders, error) {
	e := &Uploaders{}

	e.uploaders = append(e.uploaders, collectCopyUploaders(config)...)
	e.uploaders = append(e.uploaders, collectS3Uploaders(config)...)
	e.uploaders = append(e.uploaders, collectNoopUploaders(config)...)

	return e, nil
}

// NewUploadersFromUploaderArray creates a new instance of an Uploaders object from a list of Uploader instances
func NewUploadersFromUploaderArray(uploaders []Uploader) *Uploaders {
	e := &Uploaders{
		uploaders: make([]Uploader, len(uploaders)),
	}
	copy(e.uploaders, uploaders)
	return e
}

// Performs a parallel upload of all of files in a directory but
// not its subdirectories. A slice containing the error results for
// each upload with an error is returned.
func uploadDir(uploader Uploader, local string, remote string, ctypeFunc ContentTypeInferenceFunction) []error {
	var errs []error

	fi, err := os.Stat(local)
	if err != nil {
		return append(errs, err)
	}

	if fi.IsDir() {
		finfos, err := ioutil.ReadDir(local)
		if err != nil {
			return append(errs, err)
		}
		// Iterate over each file and upload it
		for _, finfo := range finfos {
			if finfo.IsDir() {
				continue // don't upload subdirs
			}

			qlocal := path.Join(local, finfo.Name())
			qremote := path.Join(remote, finfo.Name())

			log.Printf("Uploading log file %s to %s", qlocal, qremote)
			if err = uploader.Upload(qlocal, qremote, ctypeFunc); err != nil {
				uploadErr := fmt.Errorf("Error uploading to %s: %s", qremote, err)
				log.Printf("%s", uploadErr)
				errs = append(errs, uploadErr)
			}
		}
	}
	return errs
}

// Upload is used to run each of uploaders available. A slice containing
// the error results for each upload with an error is returned.
func (e *Uploaders) Upload(local, remote string, ctypeFunc ContentTypeInferenceFunction) []error {
	var errs []error

	fi, staterr := os.Stat(local)
	if staterr != nil {
		errs = append(errs, staterr)
		return errs
	}

	if fi.IsDir() {
		for _, uploader := range e.uploaders {
			errs = uploadDir(uploader, local, remote, ctypeFunc)
		}
	} else {
		for _, uploader := range e.uploaders {
			log.Printf("uploading %s to %s", local, remote)
			uploadErrMsg := uploader.Upload(local, remote, ctypeFunc)
			if uploadErrMsg != nil {
				uploadErr := fmt.Errorf("Error uploading to %s : %s", remote, uploadErrMsg)
				errs = append(errs, uploadErr)
			}
		}
	}
	return errs
}

// UploadPartOfFile wraps the uploaders, and calls the UploadPartOfFile method on them. It can upload a subset of a file. Offsets are not preserved.
func (e *Uploaders) UploadPartOfFile(local io.ReadSeeker, start, length int64, remote, contentType string) []error {
	var errs []error

	for _, uploader := range e.uploaders {
		log.Debugf("uploading %s to %s", local, remote)
		uploadErrMsg := uploader.UploadPartOfFile(local, start, length, remote, contentType)
		if uploadErrMsg != nil {
			uploadErr := fmt.Errorf("Error uploading to %s : %s", remote, uploadErrMsg)
			errs = append(errs, uploadErr)
		}
	}

	return errs
}
