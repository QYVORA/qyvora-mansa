// Package events implements the shared QYVORA JSONL event envelope.
// Every emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...","framework":"mansa","level":"info","event":"scan.started","data":{}}
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"
)

const SchemaVersion = "1.0"

// Event names. Shared verbs use the ecosystem spelling exactly.
const (
	ScanStarted           = "scan.started"
	ScanCompleted         = "scan.completed"
	StageStarted          = "stage.started"
	StageCompleted        = "stage.completed"
	InterfaceDiscovered   = "interface.discovered"
	NetworkDiscovered     = "network.discovered"
	AccessPointDiscovered = "access_point.discovered"
	ClientDiscovered      = "client.discovered"
	ObservationCollected  = "observation.collected"
	TrafficObserved       = "traffic.observed"
	AnalysisCompleted     = "analysis.completed"
	FindingDiscovered     = "finding.discovered"
	EvidenceCollected     = "evidence.collected"
	RiskCalculated        = "risk.calculated"
	ReportGenerated       = "report.generated"
	Warning               = "warning"
	Error                 = "error"
)

const (
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Event is the wire shape of one event line.
type Event struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	ExecutionID   string         `json:"execution_id"`
	Framework     string         `json:"framework"`
	Level         string         `json:"level"`
	Event         string         `json:"event"`
	Data          map[string]any `json:"data,omitempty"`
}

// Stream writes events as JSONL to w. It is safe for concurrent use.
type Stream struct {
	mu          sync.Mutex
	w           io.Writer
	executionID string
}

// NewStream returns a stream bound to a freshly generated execution id.
func NewStream(w io.Writer) *Stream {
	return &Stream{w: w, executionID: newExecutionID()}
}

// ExecutionID returns the unique id for this event stream session.
func (s *Stream) ExecutionID() string {
	if s == nil {
		return ""
	}
	return s.executionID
}

// Emit writes one event. Data may be nil.
func (s *Stream) Emit(level, name string, data map[string]any) {
	if s == nil || s.w == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ev := Event{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ExecutionID:   s.executionID,
		Framework:     "mansa",
		Level:         level,
		Event:         name,
		Data:          data,
	}
	enc := json.NewEncoder(s.w)
	_ = enc.Encode(ev)
}

// Info is a convenience wrapper for level=info.
func (s *Stream) Info(name string, data map[string]any) { s.Emit(LevelInfo, name, data) }

// Warn is a convenience wrapper for level=warning.
func (s *Stream) Warn(name string, data map[string]any) { s.Emit(LevelWarning, name, data) }

// Fail is a convenience wrapper for level=error.
func (s *Stream) Fail(name string, data map[string]any) { s.Emit(LevelError, name, data) }

func newExecutionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "mansa-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
