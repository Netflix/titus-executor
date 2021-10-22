package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Netflix/metrics-client-go/metrics"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

type dockerPuller func(context.Context, metrics.Reporter, *docker.Client, string) error

func pullWithRetries(ctx context.Context, metrics metrics.Reporter, client *docker.Client, qualifiedImageName string, puller dockerPuller) error {
	var err error

	for sleep := 0; sleep < 5; sleep++ {
		// The initial sleep wil be 0
		if sleepErr := sleepWithCtx(ctx, time.Second*1<<uint(sleep)-1); sleepErr != nil {
			return err
		}

		err = puller(ctx, metrics, client, qualifiedImageName)
		if err == nil {
			return nil
		} else if isBadImageErr(err) {
			return &runtimeTypes.RegistryImageNotFoundError{Reason: err}
		}
	}

	return err

}

func isBadImageErr(err error) bool {
	return strings.Contains(err.Error(), "not found") ||
		strings.Contains(err.Error(), "invalid reference format")
}

func doDockerPull(ctx context.Context, metrics metrics.Reporter, client *docker.Client, ref string) error {
	resp, err := client.ImagePull(ctx, ref, types.ImagePullOptions{})
	defer func() {
		if resp != nil {
			// We really don't care what the error is here, we can't do anything about it
			shouldClose(resp)
		}
	}()
	if err != nil {
		metrics.Counter("titus.executor.dockerPullImageError", 1, nil)
		log.Warningf("Error pulling image '%s', due to reason: %+v", ref, err)
		return err
	}

	// This is an odd case, and it (probably) shouldn't happen
	if resp == nil {
		log.Warning("Error-free pull from Docker client resulted in nil response")
		return nil
	}
	decoder := json.NewDecoder(resp)

	pullMessages := []map[string]interface{}{}

	// Wait for EOF, or error..
	for {
		var msg map[string]interface{}

		if err = decoder.Decode(&msg); err == io.EOF {
			// Success, pull is finished
			return nil
		} else if err != nil {
			// Something unknown went wrong
			log.Warning("Error pulling image: ", err)
			for _, pullMessage := range pullMessages {
				log.Warning("Pull Message: ", pullMessage)
			}
			return err
		}
		pullMessages = append(pullMessages, msg)
		if errorMessage, ok := msg["error"]; ok {
			log.Warning("Pull error message: ", msg)
			return fmt.Errorf("Error while pulling Docker image: %s", errorMessage)
		}
	}
}
