package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/golang/protobuf/proto"
)

func checkTaskIdentityPayload(taskIdent *titus.TaskIdentity) error {
	if taskIdent.Ipv4Address == nil || *taskIdent.Ipv4Address == "" {
		return errors.New("field 'IPv4Address' unset")
	}

	if taskIdent.UnixTimestampSec == nil || *taskIdent.UnixTimestampSec == uint64(0) {
		return errors.New("field 'UnixTimestampSec' unset")
	}

	// TODO: fill in more

	return nil
}

// This implements a fake metatron identity service for testing. It fetches the task identity
// document, does a small amount of validation, and writes it in JSON to `/task-identity`.
func main() {
	sleep := flag.Int("sleep", 0, "sleep for this many seconds after fetching")
	flag.Parse()

	res, err := http.Get("http://169.254.169.254/nflx/v1/task-identity")
	if err != nil {
		panic(err)
	}
	defer res.Body.Close() // nolint: errcheck

	if res.StatusCode != 200 {
		panic(fmt.Errorf("expected 200 from task identity endpoint, but got %d", res.StatusCode))
	}

	docBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	taskIdentDoc := new(titus.TaskIdentityDocument)
	if err = proto.Unmarshal(docBytes, taskIdentDoc); err != nil {
		panic(err)
	}

	taskIdent := new(titus.TaskIdentity)
	if err = proto.Unmarshal(taskIdentDoc.Identity, taskIdent); err != nil {
		panic(err)
	}

	f, err := os.OpenFile("/task-identity", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644) // nolint: gosec
	if err != nil {
		panic(err)
	}
	defer f.Close() // nolint: errcheck

	if err = json.NewEncoder(f).Encode(taskIdent); err != nil {
		panic(err)
	}

	if err = checkTaskIdentityPayload(taskIdent); err != nil {
		panic(err)
	}

	if *sleep != 0 {
		time.Sleep(time.Duration(*sleep) * time.Second)
	}
}
