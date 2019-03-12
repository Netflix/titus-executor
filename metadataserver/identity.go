package metadataserver

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/metrics"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

func (ms *MetadataServer) generateTaskIdentity() *titus.TaskIdentity {
	now := uint64(time.Now().Unix())
	taskStatus := titus.TaskInfo_RUNNING
	ipv4Address := ms.ipv4Address.String()
	return &titus.TaskIdentity{
		Container:   ms.container,
		Ipv4Address: &ipv4Address,
		Task: &titus.TaskInfo{
			ContainerId: ms.container.RunState.TaskId,
			TaskId:      ms.container.RunState.TaskId,
			HostName:    ms.container.RunState.HostName,
			Status:      &taskStatus,
		},
		UnixTimestampSec: &now,
	}
}

func (ms *MetadataServer) taskIdentity(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.task-identity.count")

	w.Header().Set("Content-Type", "application/octet-stream")
	taskIdent := ms.generateTaskIdentity()

	identData, err := proto.Marshal(taskIdent)
	if err != nil {
		log.WithError(err).Errorf("Error marshaling task identity protobuf: %+v, task identity: %+v", err, taskIdent)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sig, err := ms.signer.Sign(identData)
	if err != nil {
		log.WithError(err).Error("Error signing data")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	taskIdentDoc := &titus.TaskIdentityDocument{
		Identity:  identData,
		Signature: sig,
	}

	ret, err := proto.Marshal(taskIdentDoc)
	if err != nil {
		log.WithError(err).Error("Unable to marshal task identity doc")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err = w.Write(ret); err != nil {
		log.WithError(err).Error("Error writing response")
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (ms *MetadataServer) taskIdentityJSON(w http.ResponseWriter, r *http.Request) {
	metrics.PublishIncrementCounter("handler.task-identity-json.count")

	w.Header().Set("Content-Type", "application/json")

	taskIdent := ms.generateTaskIdentity()
	identData, err := proto.Marshal(taskIdent)
	if err != nil {
		log.WithError(err).Errorf("Error marshaling task identity protobuf: %+v, task identity: %+v", err, taskIdent)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sig, err := ms.signer.SignString(identData)
	if err != nil {
		log.WithError(err).Error("Error signing data")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	taskIdentDoc := &titus.TaskIdentityStringDocument{
		Identity:  taskIdent,
		Signature: sig,
	}

	jEncoder := json.NewEncoder(w)
	if err := jEncoder.Encode(taskIdentDoc); err != nil {
		log.WithError(err).Error("Error encoding json")
		w.WriteHeader(http.StatusInternalServerError)
	}
}
