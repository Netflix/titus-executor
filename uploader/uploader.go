package uploader

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/Netflix/metrics-client-go/metrics"
	"github.com/Netflix/titus-executor/config"
	log "github.com/sirupsen/logrus"
)

// Wraps the backends used to do log uploading.
type Uploader struct {
	backend Backend
}

// Config specifies the config for the uploader
type Config struct {
	DisableUpload bool
	S3WriterRole  string
	S3BucketName  string
	S3PathPrefix  string
}

// The upload always prefers s3, then copy, and will use a black hole sink if nothing else is configured. The first
// s3 location or copy destination specified is used. Rest are ignored.
func NewUploader(config *config.Config, uploaderConfig *Config, iamRole string, taskID string, m metrics.Reporter) (*Uploader, error) {
	bucketName, useTitusRole := "", true

	if uploaderConfig.DisableUpload {
		return NewUploaderWithBackend(NewNoopBackend()), nil
	}

	if len(config.S3Uploaders) > 0 {
		bucketName = config.S3Uploaders[0]
	}

	if uploaderConfig.S3BucketName != "" {
		bucketName = uploaderConfig.S3BucketName
		useTitusRole = false
	}

	if bucketName != "" {
		s3, err := NewS3Backend(m, bucketName, uploaderConfig.S3PathPrefix, iamRole, taskID, uploaderConfig.S3WriterRole, useTitusRole)
		if err != nil {
			return nil, err
		}
		return NewUploaderWithBackend(s3), nil
	}

	if len(config.CopyUploaders) > 0 {
		return NewUploaderWithBackend(NewCopyBackend(config.CopyUploaders[0])), nil
	}

	return NewUploaderWithBackend(NewNoopBackend()), nil
}

func NewUploaderWithBackend(backend Backend) *Uploader {
	return &Uploader{backend}
}

type uploadFileInfo struct {
	src  string
	dest string
}

// Upload of all of files in a directory but not its subdirectories. Performs the uploads in parallel.
func uploadDir(ctx context.Context, uploader Backend, local string, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	var errs *multierror.Error
	fileUploadJobs := []uploadFileInfo{}
	const concurrentUploaders = 8

	fi, err := os.Stat(local)
	if err != nil {
		errs = multierror.Append(errs, err)
	}

	if fi.IsDir() {
		finfos, err := ioutil.ReadDir(local)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			log.WithField("file", local).Info("is a directory - to read files")
			//uploadErrs := make([]error, len(finfos))
			uploadErrs := make(map[string]error)
			// Iterate over each file and setup the work
			var wg sync.WaitGroup

			for _, finfo := range finfos {
				if finfo.IsDir() {
					continue // don't upload subdirs
				}
				srcFile := path.Join(local, finfo.Name())
				fileUploadJobs = append(fileUploadJobs, uploadFileInfo{srcFile, path.Join(remote, finfo.Name())})
			}

			// Fill up a buffering channel, so we can drain slowly
			uploadFileC := make(chan uploadFileInfo, len(fileUploadJobs))
			for _, j := range fileUploadJobs {
				uploadFileC <- j
			}
			close(uploadFileC)

			// How many workers do we need
			uploadWorkers := concurrentUploaders
			if len(fileUploadJobs) < uploadWorkers {
				uploadWorkers = len(fileUploadJobs)
			}
			wg.Add(uploadWorkers)

			// Define what the worker should do
			uploadWork := func(ch <-chan uploadFileInfo) {
				defer wg.Done()
				for job := range ch {
					if err = uploader.Upload(ctx, job.src, job.dest, ctypeFunc); err != nil {
						log.WithField("local", job.src).WithField("remote", job.dest).Error(err)
						uploadErrs[job.src] = err
					}
				}
			}

			// Start the workers
			for i := 0; i < uploadWorkers; i++ {
				go uploadWork(uploadFileC)
			}

			wg.Wait()

			for _, v := range uploadErrs {
				if err != nil {
					errs = multierror.Append(errs, v)
				}
			}
		}
	}
	return errs.ErrorOrNil()
}

// Upload uploads the file, or all the files in a directory to the remote location.
func (e *Uploader) Upload(ctx context.Context, local, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	fi, err := os.Stat(local)
	if err != nil {
		return err
	}

	if fi.IsDir() {
		log.WithField("Going to upload ", local).WithField("to remote", remote).Info(" - directory")
		return uploadDir(ctx, e.backend, local, remote, ctypeFunc)
	}

	log.WithField("local", local).WithField("remote", remote).Info("uploading a file")
	return e.backend.Upload(ctx, local, remote, ctypeFunc)
}

// UploadPartOfFile logs the call and forwards to the backend. It can upload a subset of a file. Offsets are not preserved.
func (e *Uploader) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	log.WithField("local", local).WithField("remote", remote).Infof("uploading %d,%d", start, length)
	return e.backend.UploadPartOfFile(ctx, local, start, length, remote, contentType)
}
