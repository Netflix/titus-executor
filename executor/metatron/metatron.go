package metatron

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	passportScript         = "/apps/metatron-identity/bin/getWorkloadPassports.sh" // nolint: gas
	passportPath           = "/run/titus-client-passports"
	legacyMetatronPath     = "/run/shm/metatron"
	metatronPath           = "/run/metatron"
	truststorePath         = "/metatron"
	metatronRequestType    = "titus"
	metatronRequestVersion = 1
)

type legacySymlinkFileinfo struct{}

func (legacySymlinkFileinfo) Name() string       { return legacyMetatronPath }
func (legacySymlinkFileinfo) Size() int64        { return 0 }
func (legacySymlinkFileinfo) Mode() os.FileMode  { return os.ModeSymlink }
func (legacySymlinkFileinfo) ModTime() time.Time { return time.Time{} }
func (legacySymlinkFileinfo) IsDir() bool        { return false }
func (legacySymlinkFileinfo) Sys() interface{}   { return nil }

var whitelistDirs = map[string]bool{"/metatron": true, "/metatron/certificates": true}

// TrustStore encapsulates the state of metatron
type TrustStore struct {
	truststoreTarBuf *bytes.Buffer
}

// InitMetatronTruststore initializes cached trust store data
func InitMetatronTruststore() (*TrustStore, error) {
	mts := &TrustStore{}
	mts.truststoreTarBuf = new(bytes.Buffer)
	// Create and cache trust store tar bytes for Docker. These certs are
	// baked into the AMI and are meant to be long lived.
	truststoreTW := tar.NewWriter(mts.truststoreTarBuf)
	defer func() {
		if err := truststoreTW.Close(); err != nil {
			log.Fatal("Failed to close tar writer while creating Metatron trust store tar: ", err)
		}
	}()

	if err := walkTruststore(truststoreTW); err != nil {
		return nil, err
	}

	return mts, nil
}

func walkTruststore(tw *tar.Writer) error { // nolint: gocyclo
	// Add symlink from legacy path to current path
	symlinkHeader, err := tar.FileInfoHeader(legacySymlinkFileinfo{}, metatronPath)
	if err != nil {
		return err
	}

	if err = tw.WriteHeader(symlinkHeader); err != nil {
		return err
	}

	// Iterate the Metatron trust store path and add contents to the tar
	return filepath.Walk(truststorePath, func(path string, fileInfo os.FileInfo, inErr error) error {
		var (
			data    []byte
			written int
		)

		if inErr != nil {
			return inErr
		}

		header, err := tar.FileInfoHeader(fileInfo, fileInfo.Name())
		if err != nil {
			return err
		}
		// Add full path name to header, not base name
		header.Name = path

		// Skip non-whitelisted dirs, symlinks, etc.
		if !fileInfo.Mode().IsRegular() && !whitelistDirs[path] {
			return nil
		}

		if err = tw.WriteHeader(header); err != nil {
			return err
		}

		if fileInfo.IsDir() {
			return nil
		}

		data, err = ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		written, err = tw.Write(data)
		if err != nil {
			return err
		}
		if int64(written) != header.Size {
			return fmt.Errorf("Failed to fully write file %s to Metatron tar: Only write %d bytes of %d", path, written, header.Size)
		}

		return nil
	})
}

// TitusMetadata contains values received from Master and generated
// during task setup about what is being run
type TitusMetadata struct {
	App          string            `json:"app"`
	Stack        string            `json:"stack"`
	ImageName    string            `json:"imageName"`
	ImageVersion string            `json:"imageVersion"`
	ImageDigest  string            `json:"imageDigest"`
	Entrypoint   []string          `json:"entry,omitempty"`
	Command      []string          `json:"command,omitempty"`
	Env          map[string]string `json:"env"`
	TaskID       string            `json:"instanceId"`
	LaunchTime   int64             `json:"launchTime"`
	IPAddress    string            `json:"ipAddress"`
}

// PassportRequest contains the fields
type PassportRequest struct {
	Version        uint32        `json:"VERSION"`
	RequestType    string        `json:"TYPE"`
	AppMetadataSig string        `json:"NETFLIX_APP_METADATA_SIG"`
	AppMetadata    string        `json:"NETFLIX_APP_METADATA"`
	OutputPath     string        `json:"OUTPUT_PATH"`
	TitusMetadata  TitusMetadata `json:"TYPE_METADATA"`
}

// CredentialsConfig contains the config info for a runtime to inject credentials
type CredentialsConfig struct {
	// HostCredentialsPath is the path to the credentials directory on the host
	HostCredentialsPath string
	// TaskCredentialsPath is the path to the credentials directory in the task
	HostCredentialsPrefix string
	// TruststoreTarBuf is a tar buffer of the trust store certs. Meant for Docker runtime.
	TruststoreTarBuf *bytes.Buffer
}

func getPassportHostPath(taskID string) string {
	return fmt.Sprintf("%s/%s/", passportPath, taskID)
}

func getMetatronOutputPath(taskID string) string {
	return getPassportHostPath(taskID) + metatronPath
}

// CreatePassportDir creates a directory to store a task's Metatron
// credentials on the host
func createPassportDir(taskID string) error {
	return os.MkdirAll(getMetatronOutputPath(taskID), os.FileMode(0700))
}

// GetPassports gets Metatron passports for a container/task and stores
// them in a file system location.
func (mts *TrustStore) GetPassports(ctx context.Context, encodedAppMetadata string, encodedAppSig string, titusMetadata TitusMetadata) (*CredentialsConfig, error) {
	var (
		err    error
		taskID = titusMetadata.TaskID
	)

	// Create a writeable directory path for the passports to go
	if err = createPassportDir(taskID); err != nil {
		return nil, err
	}

	// Create the request to pass into the script
	outputPath := getMetatronOutputPath(taskID)
	passportRequest := PassportRequest{
		Version:        metatronRequestVersion,
		RequestType:    metatronRequestType,
		AppMetadata:    encodedAppMetadata,
		AppMetadataSig: encodedAppSig,
		OutputPath:     outputPath,
		TitusMetadata:  titusMetadata,
	}
	// Convert the passportRequest to JSON and write to the command
	var encodedRequest []byte
	if encodedRequest, err = json.Marshal(passportRequest); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, passportScript) // nolint: gas

	var stdin io.WriteCloser
	if stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}

	go func() {
		defer func() {
			if err = stdin.Close(); err != nil {
				log.Errorf("Failed to close stdin to Metatron passport script")
			}
		}()
		log.Debugf("Writing %s to stdin of %s", string(encodedRequest), passportScript)
		var bytesWritten int
		// If we failed to write to stdin we expect the command to exit unsuccessfully
		// so we can just log the failure here.
		if bytesWritten, err = io.WriteString(stdin, string(encodedRequest)); err != nil {
			log.Errorf("Failed to write to Metatron passport script stdin: %s", err)
		} else if bytesWritten != len(encodedRequest) {
			log.Errorf("Failed to write %d byte to stdin, only wrote %d", len(encodedRequest), bytesWritten)
		}
	}()

	// Start the command but don't wait for completion. We expect
	// it to wait for stdin input.
	if err = cmd.Start(); err != nil {
		return nil, err
	}

	// An error is returned for an non-zero exit value
	if err = cmd.Wait(); err != nil {
		return nil, fmt.Errorf("Failed to run Metatron passport certificates script: %s", err)
	}

	return &CredentialsConfig{
		HostCredentialsPath:   outputPath,
		HostCredentialsPrefix: getPassportHostPath(taskID),
		TruststoreTarBuf:      mts.truststoreTarBuf,
	}, nil
}
