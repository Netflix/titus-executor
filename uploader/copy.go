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
	return u.uploadFile(l, remote, contentType)
}

// UploadFile copies a single file only!
func (u *CopyUploader) uploadFile(local io.Reader, remote, contentType string) error {
	fullremote := path.Join(u.Dir, remote)
	log.Println("copy : local io.Reader -> " + fullremote)

	remoteDir := path.Dir(fullremote)
	if err := os.MkdirAll(remoteDir, 0777); err != nil { // nolint: gosec
		return err
	}

	r, err := os.Create(fullremote)
	if err != nil {
		return err
	}
	defer func() {
		if err = r.Close(); err != nil {
			log.Printf("Failed to close %s: %s", r.Name(), err)
		}
	}()

	if contentType != "" {
		err = xattr.FSetXattr(r, xattr.MimeTypeAttr, []byte(contentType))
		if err != nil {
			log.Warning("Unable to set content type: ", err)
		}
	}
	_, err = io.Copy(r, local)
	return err
}

// UploadPartOfFile copies a single file only. It doesn't preserve the cursor location in the file.
func (u *CopyUploader) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if n, err := local.Seek(start, io.SeekStart); err != nil {
		return err
	} else if n != start {
		return errors.New("Could not seek")
	}
	limitLocal := io.LimitReader(local, length)
	return u.uploadFile(limitLocal, remote, contentType)
}
