// Package events implements the shared QYVORA JSONL event envelope.
// Every emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...","framework":"mansa","level":"info","event":"scan.started","data":{}}
package events

import (
	"io"

	shared "github.com/QYVORA/qyvora-events"
)

const SchemaVersion = shared.SchemaVersion

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
	LevelInfo    = shared.LevelInfo
	LevelWarning = shared.LevelWarning
	LevelError   = shared.LevelError
)

type Event = shared.Event
type Stream = shared.Stream

// NewStream returns a stream bound to mansa.
func NewStream(w io.Writer) *Stream { return shared.NewStream(w, "mansa") }
