package uploader

import (
	"errors"
	"io"
	"os"
	"path"

	"context"

	"github.com/Netflix/titus-executor/filesystems/xattr"
	log "github.com/sirupsen/logrus"
)

type destinationFile interface {
	// File gets the underlying file object
	File() *os.File
	// Finish indicates that file handling is done. It makes the file visible to other users
	Finish() error
}

// CopyUploader is an uploader that just copies files to another
// location on the same host
type CopyUploader struct {
	Dir string `json:"directory"`
}

// NewCopyUploader creates a new instance of a copy uploader
func NewCopyUploader(directory string) Uploader {
	return &CopyUploader{Dir: directory}
}

// Upload copies a single file only!
func (u *CopyUploader) Upload(ctx context.Context, local, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	l, err := os.Open(local) // nolint: gosec
	if err != nil {
		return err
	}
	defer func() {
		if err = l.Close(); err != nil {
			log.Warningf("Failed to close %s: %s", l.Name(), err)
		}
	}()

	contentType := ctypeFunc(local)

	// copy uploader doesn't understand content types, ignore it
	_, err = u.uploadFile(l, remote, contentType)
	return err
}

// UploadFile copies a single file only!
func (u *CopyUploader) uploadFile(local io.Reader, remote, contentType string) (int64, error) {
	fullremote := path.Join(u.Dir, remote)
	log.Println("copy : local io.Reader -> " + fullremote)

	remoteDir := path.Dir(fullremote)
	if err := os.MkdirAll(remoteDir, 0777); err != nil { // nolint: gosec
		return 0, err
	}

	r, err := newDestinationFile(fullremote, 0644)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err = r.File().Close(); err != nil {
			log.Printf("Failed to close %s: %s", r.File().Name(), err)
		}
	}()

	if contentType != "" {
		err = xattr.FSetXattr(r.File(), xattr.MimeTypeAttr, []byte(contentType))
		if err != nil {
			log.Warning("Unable to set content type: ", err)
		}
	}
	n, err := io.Copy(r.File(), local)
	if err != nil {
		return 0, err
	}
	return n, r.Finish()
}

// UploadPartOfFile copies a single file only. It doesn't preserve the cursor location in the file.
func (u *CopyUploader) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	entry := log.WithFields(map[string]interface{}{
		"start":  start,
		"length": length,
		"remote": remote,
	})
	if err := ctx.Err(); err != nil {
		return err
	}

	if n, err := local.Seek(start, io.SeekStart); err != nil {
		return err
	} else if n != start {
		return errors.New("Could not seek")
	}
	entry.Debug("Uploading part of file")
	limitLocal := io.LimitReader(local, length)
	n, err := u.uploadFile(limitLocal, remote, contentType)
	entry.WithError(err).WithField("n", n).Debug("Uploaded part of file")
	return err
}
