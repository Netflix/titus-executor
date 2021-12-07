package uploader

var (
	logPublisherSBlock = &s{
		S: "titus-log-uploader",
	}
)

type batchedFirewoodLogEntries struct {
	SchemaVersion string              `json:"schema_version"`
	InfraTags     map[string]string   `json:"infra_tags,omitempty"`
	Logs          []*firewoodLogEntry `json:"logs,omitempty"`
}

type fields struct {
	AgentTs      *i64 `json:"agent_ts,omitempty"`
	LogSource    *s   `json:"log_source,omitempty"`
	LogPublisher *s   `json:"log_publisher,omitempty"`
	SequenceNum  *i64 `json:"sequence_num,omitempty"`
}

type i64 struct {
	I64 int64 `json:"i64,omitempty"`
}

type s struct {
	S string `json:"s,omitempty"`
}

type firewoodLogEntry struct {
	Fields             *fields  `json:"fields,omitempty"`
	Message            *message `json:"message,omitempty"`
	messageBytes       int
	origTimestampMicro int64
}

type message struct {
	MsgField string      `json:"msg_field,omitempty"`
	TsField  string      `json:"ts_field,omitempty"`
	TsType   string      `json:"ts_type,omitempty"`
	TsFormat string      `json:"ts_format,omitempty"`
	Payload  interface{} `json:"payload,omitempty"`
}

type genericPayload struct {
	Logger    string `json:"logger,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Message   string `json:"message,omitempty"`
	Level     string `json:"level,omitempty"`
}
