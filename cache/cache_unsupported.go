// +build !linux

package cache

import (
	"io/ioutil"
	"os"
	"path/filepath"
)

func atomicWriteOnce(path string, data []byte, mode os.FileMode) error {
	tempfile, err := ioutil.TempFile("", filepath.Base(path))
	if err != nil {
		return err
	}

	defer tempfile.Close()
	_, err = tempfile.Write(data)
	if err != nil {
		return err
	}
	err = os.Chmod(tempfile.Name(), mode)
	if err != nil {
		return err
	}

	err = tempfile.Sync()
	if err != nil {
		return err
	}

	return os.Rename(tempfile.Name(), path)
}
