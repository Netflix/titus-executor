package uploader

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Netflix/spectator-go"
	log "github.com/sirupsen/logrus"
)

type InsightLogsBackend struct {
	log         log.FieldLogger
	httpClient  *spectator.HttpClient
	firewoodURL string
}

func NewInsightLogsBackend() (Backend, error) {
	config := &spectator.Config{
		Frequency:  5 * time.Second,
		Timeout:    1 * time.Second,
		BatchSize:  10000,
		Uri:        "",
		CommonTags: getCommonTags(),
	}
	registry := spectator.NewRegistry(config)
	u := InsightLogsBackend{
		log:         log.StandardLogger(),
		httpClient:  spectator.NewHttpClient(registry, time.Duration(10)*time.Second),
		firewoodURL: getFirewoodURL(),
	}
	return &u, nil
}

func getFirewoodURL() string {
	stack := "log-publish"
	region := "us-east-1"
	env := "test"
	app := "kyleatestapp"
	return fmt.Sprintf("http://%s.%s.iep%s.netflix.net/api/v1/publish/%s", stack, region, env, app)
}

func (u *InsightLogsBackend) postBatch(batchedEntries batchedFirewoodLogEntries) error {
	b, err := json.Marshal(batchedEntries)
	if err != nil {
		return err
	}
	u.log.Infof("Insight logs Uploading %+v to %s", batchedEntries, u.firewoodURL)
	i, err := u.httpClient.PostJson(u.firewoodURL, b)
	if i != 200 {
		return fmt.Errorf("Got a %d error code from posting to firewood", i)
	}
	return err
}

func (u *InsightLogsBackend) Upload(ctx context.Context, local, remote string, ctypeFunc ContentTypeInferenceFunction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l, err := os.Open(local)
	if err != nil {
		return err
	}
	defer func() {
		if err = l.Close(); err != nil {
			log.Warningf("Failed to close %s: %s", l.Name(), err)
		}
	}()
	return u.UploadFile(ctx, l)
}

func (u *InsightLogsBackend) UploadPartOfFile(ctx context.Context, local io.ReadSeeker, start, length int64, remote, contentType string) error {
	u.log.Printf("Attempting to upload part of file (%d,%d) to insight logs", start, length)
	if err := ctx.Err(); err != nil {
		return err
	}
	limitLocal := io.LimitReader(local, length)
	return u.UploadFile(ctx, limitLocal)
}

func (u *InsightLogsBackend) UploadFile(ctx context.Context, local io.Reader) error {
	logEntries := []*firewoodLogEntry{}
	scanner := bufio.NewScanner(local)
	for scanner.Scan() {
		entry := generateFirewoodEntry(scanner.Text())
		logEntries = append(logEntries, &entry)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("Error when scanning %s: %w", local, err)
	}
	batchedEntries := batchedFirewoodLogEntries{
		SchemaVersion: "1.0.0",
		InfraTags: map[string]string{
			"nf.app": "kyleatestapp",
			"nf.env": "test",
		},
		Logs: logEntries,
	}
	_ = u.postBatch(batchedEntries)
	return nil
}

func generateFirewoodEntry(s string) firewoodLogEntry {
	entry := firewoodLogEntry{}
	tsMilli := time.Now().UTC().UnixNano() / 1000000
	entry.Message, entry.messageBytes = getMessageFromString(s, tsMilli)
	entry.Fields.LogSource.S = "kyleatestapp"
	entry.Fields.LogPublisher = logPublisherSBlock
	entry.origTimestampMicro = tsMilli * 1000
	entry.Fields.AgentTs.I64 = tsMilli * 1000
	entry.Fields.SequenceNum.I64 = tsMilli
	return entry
}

func getMessageFromString(s string, tsMilli int64) (msg *message, logEntryBytes int) {
	payload := s
	logEntryBytes = len(payload)
	msg = &message{
		MsgField: "message",
		TsField:  "timestamp",
		TsFormat: "milliseconds",
		TsType:   "EpochOffset",
		Payload: &genericPayload{
			Logger:    "titus-log-uploader",
			Timestamp: tsMilli,
			Level:     "info",
			Message:   payload,
		},
	}
	return
}

// TODO: don't copy paste this from vpc-service
func getCommonTags() map[string]string {
	commonTags := map[string]string{}
	addNonEmpty(commonTags, "nf.app", "NETFLIX_APP")
	addNonEmpty(commonTags, "nf.asg", "NETFLIX_AUTO_SCALE_GROUP")
	addNonEmpty(commonTags, "nf.cluster", "NETFLIX_CLUSTER")
	addNonEmpty(commonTags, "nf.node", "NETFLIX_INSTANCE_ID")
	addNonEmpty(commonTags, "nf.region", "EC2_REGION")
	addNonEmpty(commonTags, "nf.vmtype", "EC2_INSTANCE_TYPE")
	addNonEmpty(commonTags, "nf.zone", "EC2_AVAILABILITY_ZONE")
	addNonEmpty(commonTags, "nf.stack", "NETFLIX_STACK")
	addNonEmpty(commonTags, "nf.account", "EC2_OWNER_ID")
	return commonTags
}

// TODO: don't copy paste this from vpc-service
func addNonEmpty(tags map[string]string, key string, envVar string) {
	if value := os.Getenv(envVar); value != "" {
		tags[key] = value
	}
}
