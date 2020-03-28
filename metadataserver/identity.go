package metadataserver

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/metadataserver/identity"
	"github.com/Netflix/titus-executor/metadataserver/metrics"
	"github.com/pkg/errors"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

func (ms *MetadataServer) generateTaskIdentity() *titus.TaskIdentity {
	now := uint64(time.Now().Unix())
	taskStatus := titus.TaskInfo_RUNNING
	ti := &titus.TaskIdentity{
		Container: ms.container,
		Task: &titus.TaskInfo{
			ContainerId: ms.container.RunState.TaskId,
			TaskId:      ms.container.RunState.TaskId,
			HostName:    ms.container.RunState.HostName,
			Status:      &taskStatus,
		},
		UnixTimestampSec: &now,
	}

	if ms.ipv4Address != nil {
		ipv4Address := ms.ipv4Address.String()
		ti.Ipv4Address = &ipv4Address
	}
	if ms.ipv6Address != nil {
		ipv6Address := ms.ipv6Address.String()
		ti.Ipv6Address = &ipv6Address
	}

	return ti
}

// SetSigner updates the identity server's signer
func (ms *MetadataServer) SetSigner(newSigner *identity.Signer) error {
	newCert, err := x509.ParseCertificate(newSigner.Certificate.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "error parsing new certificate")
	}

	ms.signLock.Lock()
	defer ms.signLock.Unlock()
	oldSigner := ms.signer
	oldCert, err := x509.ParseCertificate(oldSigner.Certificate.Certificate[0])
	if err != nil {
		return errors.Wrap(err, "error parsing old certificate")
	}

	log.WithFields(log.Fields{
		"newSubject":      newCert.Subject,
		"newIssuer":       newCert.Issuer,
		"newNotBefore":    newCert.NotBefore,
		"newNotAfter":     newCert.NotAfter,
		"newSerialNumber": newCert.SerialNumber,
		"oldSubject":      oldCert.Subject,
		"oldIssuer":       oldCert.Issuer,
		"oldNotBefore":    oldCert.NotBefore,
		"oldNotAfter":     oldCert.NotAfter,
		"oldSerialNumber": oldCert.SerialNumber,
	}).Info("signer cert updated")

	ms.signer = newSigner
	return nil
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

	ms.signLock.RLock()
	sig, err := ms.signer.Sign(identData)
	ms.signLock.RUnlock()
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

	ms.signLock.RLock()
	sig, err := ms.signer.SignString(identData)
	ms.signLock.RUnlock()
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
