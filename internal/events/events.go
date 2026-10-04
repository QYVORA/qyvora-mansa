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
	ScanStarted                       = "scan.started"
	ScanCompleted                     = "scan.completed"
	StageStarted                      = "stage.started"
	StageCompleted                    = "stage.completed"
	InterfaceDiscovered               = "interface.discovered"
	NetworkDiscovered                 = "network.discovered"
	AccessPointDiscovered             = "access_point.discovered"
	ClientDiscovered                  = "client.discovered"
	AccessPointUpdated                = "access_point.updated"
	ClientUpdated                     = "client.updated"
	ClientRoamed                      = "client.roamed"
	ObservationCollected              = "observation.collected"
	TrafficObserved                   = "traffic.observed"
	WirelessAuthenticationObserved    = "wireless.authentication.observed"
	AnalysisCompleted                 = "analysis.completed"
	FindingDiscovered                 = "finding.discovered"
	EvidenceCollected                 = "evidence.collected"
	RiskCalculated                    = "risk.calculated"
	ReportGenerated                   = "report.generated"
	CaptureAnalysisStarted            = "capture.analysis.started"
	CaptureAnalysisCompleted          = "capture.analysis.completed"
	CaptureStarted                    = "capture.started"
	CaptureCompleted                  = "capture.completed"
	MonitorInterfaceCreated           = "monitor_interface.created"
	MonitorInterfaceRemoved           = "monitor_interface.removed"
	ChannelChanged                    = "wireless.channel.changed"
	BluetoothAdvertisementParsed      = "bluetooth.advertisement.parsed"
	BluetoothGATTEnumerationStarted   = "bluetooth.gatt.enumeration.started"
	BluetoothGATTEnumerationCompleted = "bluetooth.gatt.enumeration.completed"
	BluetoothGATTAnalysisStarted      = "bluetooth.gatt.analysis.started"
	BluetoothGATTAnalysisCompleted    = "bluetooth.gatt.analysis.completed"
	BluetoothAdapterDiscovered        = "bluetooth.adapter.discovered"
	BluetoothDeviceDiscovered         = "bluetooth.device.discovered"
	BluetoothDeviceUpdated            = "bluetooth.device.updated"
	BluetoothScanStarted              = "bluetooth.scan.started"
	BluetoothScanCompleted            = "bluetooth.scan.completed"
	ValidationStarted                 = "validation.started"
	ValidationCompleted               = "validation.completed"
	ActiveTestStarted                 = "active_test.started"
	ActiveTestCompleted               = "active_test.completed"
	ExploitStarted                    = "exploit.started"
	ExploitCompleted                  = "exploit.completed"
	CredentialAssessmentStarted       = "credential.assessment.started"
	CredentialCandidateTested         = "credential.candidate.tested"
	CredentialAssessmentCompleted     = "credential.assessment.completed"
	CredentialCandidateConfirmed      = "credential.candidate.confirmed"
	OperationRefused                  = "operation.refused"
	OperationCancelled                = "operation.cancelled"
	FramesTransmitted                 = "wireless.frames.transmitted"
	Warning                           = "warning"
	Error                             = "error"
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
