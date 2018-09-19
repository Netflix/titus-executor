// +build !linux

package context

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

func atomicWriteOnce(path string, data []byte) error {
	tempfile, err := ioutil.TempFile("", filepath.Base(path))
	if err != nil {
		return err
	}

	// warning: error return value not checked
	defer shouldClose(tempfile) // nolint: errcheck

	_, err = tempfile.Write(data)
	if err != nil {
		return err
	}
	err = tempfile.Sync()
	if err != nil {
		return err
	}

	return os.Rename(tempfile.Name(), path)
}
