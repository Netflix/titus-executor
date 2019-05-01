// +build !linux

package uploader

import "os"

type unsupportedDestinationFile struct {
	file *os.File
}

func (df *unsupportedDestinationFile) File() *os.File {
	return df.file
}

func (unsupportedDestinationFile) Finish() error {
	return nil
}

func newDestinationFile(filename string, mode os.FileMode) (destinationFile, error) {
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return &unsupportedDestinationFile{
		file: f,
	}, nil
}
