package runtime

//TODO(fabio): this is all Docker specific, move it to runtime/docker/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// NetworkConfigurationParams contains config input info
type NetworkConfigurationParams struct {
	ResourceID      string
	SgIds           []string
	RoutableIP      bool `json:"RoutableIp"`
	Bandwidth       uint32
	IamRole         string
	TitusInstanceID string `json:"TitusInstanceId"`
}

// NetworkConfigurationDetails used to pass results back to master
type NetworkConfigurationDetails struct {
	IsRoutableIP bool
	IPAddress    string
	EniIPAddress string
	EniID        string
	ResourceID   string
}

// NetworkConfiguration contains a container's network config info
type NetworkConfiguration struct {
	ResourceID       string
	ContainerID      string
	IPAddress        string
	GwAddress        string
	EniID            string
	InterfaceCreated bool
	EniName          string
	Created          int64
}

// NetworkConfigurationRequest represents a request to config a container's network
type NetworkConfigurationRequest struct {
	TaskID string
	Params *NetworkConfigurationParams
}

// NetworkConfigurationResponse a response to a container config request
type NetworkConfigurationResponse struct {
	Status    string
	Messages  []string
	Namespace *NetworkConfiguration
}

// NetworkCleanupRequest is a request to cleanup a container's network
type NetworkCleanupRequest struct {
	ContainerID string
}

// NetworkCleanupResponse is the result of cleaning up a container's network
type NetworkCleanupResponse struct {
	Status   string
	Messages []string
}

const clientTimeout time.Duration = time.Duration(600 * time.Second) // nolint: unconvert

// CreateNetworkConfiguration calls the network VPC driver, and creates the network namespace based on _Docker ID_
func CreateNetworkConfiguration(taskID string, params *NetworkConfigurationParams) (*NetworkConfiguration, error) {

	cfgRequest := &NetworkConfigurationRequest{
		TaskID: taskID,
		Params: params,
	}

	reqBody, err := json.Marshal(cfgRequest)
	if err != nil {
		return nil, fmt.Errorf("can not serialize request %v: %s", cfgRequest, err)
	}

	client := &http.Client{
		Timeout: clientTimeout,
	}
	proxyReq, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:6666/create"), bytes.NewBuffer(reqBody)) // nolint: ineffassign
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(proxyReq)

	defer func() {
		if resp != nil {
			if err := resp.Body.Close(); err != nil { // nolint: vetshadow
				log.Printf("Failed to close %+v: %s", resp.Body, err)
			}
		}
	}()

	if err != nil {
		return nil, fmt.Errorf("server response error: %s", err)
	}

	cfgResp := &NetworkConfigurationResponse{}
	err = json.NewDecoder(resp.Body).Decode(cfgResp)

	if err != nil {
		return nil, fmt.Errorf("can not parse response: %s", err)
	}

	if cfgResp.Status != "Ok" {
		return nil, fmt.Errorf("can not prepare network configuration: %v", cfgResp.Messages)
	}

	return cfgResp.Namespace, nil
}

// CleanupNetworkConfiguration calls the network VPC driver, and cleans up the namespace based on _Docker ID_
func CleanupNetworkConfiguration(containerID string) error {
	cleanupRequest := &NetworkCleanupRequest{
		ContainerID: containerID,
	}

	reqBody, err := json.Marshal(cleanupRequest)
	if err != nil {
		return fmt.Errorf("can not serialize request %v: %s", cleanupRequest, err)
	}

	client := &http.Client{
		Timeout: clientTimeout,
	}
	proxyReq, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:6666/remove"), bytes.NewBuffer(reqBody)) // nolint: ineffassign
	if err != nil {
		return err
	}
	resp, err := client.Do(proxyReq)

	defer func() {
		if resp != nil {
			if err := resp.Body.Close(); err != nil { // nolint: vetshadow
				log.Printf("Failed to close %+v: %s", resp.Body, err)
			}
		}
	}()

	if err != nil {
		return fmt.Errorf("server response error: %s", err)
	}

	cleanupResp := &NetworkCleanupResponse{}
	err = json.NewDecoder(resp.Body).Decode(cleanupResp)

	if err != nil {
		return fmt.Errorf("can not parse response: %s", err)
	}

	if cleanupResp.Status != "Ok" {
		return fmt.Errorf("can not prepare network configuration: %+v", cleanupResp.Messages)
	}

	return nil
}
