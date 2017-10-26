package uploader

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"io"

	log "github.com/sirupsen/logrus"
)

// NewUploader creates a new instance of an uploader object
func NewUploader(config map[string]string) (Uploader, error) {
	var up Uploader
	var err error
	switch config["type"] {
	case "copy":
		if up, err = NewCopyUploader(config); err != nil {
			return nil, err
		}
		return up, nil
	case "s3":
		if up, err = NewS3Uploader(log.StandardLogger(), config); err != nil {
			return nil, err
		}
		return up, nil
	case "noop":
		if up, err = NewNoopUploader(config); err != nil {
			return nil, err
		}
		return up, nil
	default:
		return nil, errors.New("invalid config type : " + config["type"])
	}
}

// Uploaders is a slice wrapper that contains all of the
// uploaders to use when tasks complete
type Uploaders struct {
	uploaders []Uploader
}

// NewUploaders creates a new instance of an Uploaders object
func NewUploaders(configs []map[string]string) (*Uploaders, error) {
	e := &Uploaders{}
	var up Uploader
	var err error
	for _, uploader := range configs {
		if up, err = NewUploader(uploader); err != nil {
			return nil, err
		}
		e.uploaders = append(e.uploaders, up)
	}
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
func uploadDir(uploader Uploader, local string, remote string, contentType string) []error {
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
			if err = uploader.Upload(qlocal, qremote, contentType); err != nil {
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
func (e *Uploaders) Upload(local, remote, contentType string) []error {
	var errs []error

	fi, staterr := os.Stat(local)
	if staterr != nil {
		errs = append(errs, staterr)
		return errs
	}

	if fi.IsDir() {
		for _, uploader := range e.uploaders {
			errs = uploadDir(uploader, local, remote, contentType)
		}
	} else {
		for _, uploader := range e.uploaders {
			log.Printf("uploading %s to %s", local, remote)
			uploadErrMsg := uploader.Upload(local, remote, contentType)
			if uploadErrMsg != nil {
				uploadErr := fmt.Errorf("Error uploading to %s : %s", remote, uploadErrMsg)
				errs = append(errs, uploadErr)
			}
		}
	}
	return errs
}

// UploadFile wraps the uploaders, and calls the UploadFile method on them. It Requires an IO Reader to function
func (e *Uploaders) UploadFile(local io.Reader, remote, contentType string) []error {
	var errs []error

	for _, uploader := range e.uploaders {
		log.Debugf("uploading %s to %s", local, remote)
		uploadErrMsg := uploader.UploadFile(local, remote, contentType)
		if uploadErrMsg != nil {
			uploadErr := fmt.Errorf("Error uploading to %s : %s", remote, uploadErrMsg)
			errs = append(errs, uploadErr)
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
