package models

import "time"

// NoiseLevel describes the operational footprint of a module from an OPSEC
// perspective. It answers: how visible is this module to a defending
// adversary, assuming they are monitoring the target environment?
//
// Noise level is independent of risk: a passive-noise reconnaissance module may
// still carry medium risk if it discloses the assessment, while an
// aggressive-noise exploit definitionally carries high risk because it affects
// the target.
type NoiseLevel string

const (
	// NoiseLevelPassive observes only, emitting nothing detectable.
	NoiseLevelPassive NoiseLevel = "passive"
	// NoiseLevelLow emits minimal detectable activity: a single probe frame, a
	// standards-compliant association, or enumeration that blends with normal
	// client behavior.
	NoiseLevelLow NoiseLevel = "low"
	// NoiseLevelModerate emits detectable non-hostile activity: rapid scanning,
	// repeated probes, or traffic patterns distinguishable from a normal client
	// but not inherently adversarial.
	NoiseLevelModerate NoiseLevel = "moderate"
	// NoiseLevelAggressive emits obviously hostile activity: frame injection,
	// denial of service, impersonation, or any transmission that unambiguously
	// signals an active assessment.
	NoiseLevelAggressive NoiseLevel = "aggressive"
)

// String renders the noise level name used in records, events, and CLI output.
func (n NoiseLevel) String() string {
	return string(n)
}

// OperationClass distinguishes how strongly an operation affects the target
// environment. The class is part of Mansa's security model: it decides whether
// an explicit authorization gate applies and how a result may be described.
// Passive collection is never an operation module, so it is declared only so
// that the four classes stay comparable in machine-readable output.
type OperationClass string

const (
	// ClassPassive only observes. It is never used by an operation module.
	ClassPassive OperationClass = "passive"
	// ClassValidation confirms or refutes an observed condition using the
	// smallest interaction that can answer the question.
	ClassValidation OperationClass = "validation"
	// ClassActiveTest deliberately exercises a target's security controls.
	ClassActiveTest OperationClass = "active_test"
	// ClassExploitation drives an authorized target toward a known outcome in
	// order to prove exploitability, not merely to observe it.
	ClassExploitation OperationClass = "exploitation"
)

// AffectsTargetEnvironment reports whether the class emits radio traffic or
// otherwise changes state outside the assessment host. Every class that does is
// refused unless the run carries an explicitly authorized target.
// String renders the class name used in records, events, and CLI output.
func (c OperationClass) String() string {
	switch c {
	case ClassPassive:
		return "passive"
	case ClassValidation:
		return "validation"
	case ClassActiveTest:
		return "active_test"
	case ClassExploitation:
		return "exploitation"
	default:
		return string(c)
	}
}

func (c OperationClass) AffectsTargetEnvironment() bool {
	return c == ClassActiveTest || c == ClassExploitation
}

// RequiresConfirmation reports whether a run of this class should be confirmed
// before execution because it emits traffic.
func (c OperationClass) RequiresConfirmation() bool { return c.AffectsTargetEnvironment() }

// OperationStatus is the terminal state of one operation run.
type OperationStatus string

const (
	// StatusPlanned means the module resolved and validated the request but
	// nothing was executed, as with a dry run.
	StatusPlanned OperationStatus = "planned"
	// StatusUnavailable means the host or adapter cannot satisfy the module's
	// declared hardware requirements. It is never reported as a pass.
	StatusUnavailable OperationStatus = "unavailable"
	StatusRefused     OperationStatus = "refused"
	StatusCompleted   OperationStatus = "completed"
	StatusFailed      OperationStatus = "failed"
	StatusCancelled   OperationStatus = "cancelled"
)

// CleanupState records what happened to the radio state an operation touched.
type CleanupState string

const (
	CleanupNotRequired CleanupState = "not_required"
	CleanupCompleted   CleanupState = "completed"
	CleanupFailed      CleanupState = "failed"
	CleanupPending     CleanupState = "pending"
)

// OperationRecord is the persisted audit record for one operation run. It
// carries the target, scope, authorization state, execution correlation, and
// cleanup state so an active run can be reviewed after the fact without
// reading the event stream.
type OperationRecord struct {
	ID       string          `json:"id"`
	ModuleID string          `json:"module_id"`
	Title    string          `json:"title,omitempty"`
	Class    OperationClass  `json:"class"`
	Domain   string          `json:"domain"`
	Risk     string          `json:"risk"`
	Status   OperationStatus `json:"status"`

	Target     string     `json:"target"`
	TargetType TargetType `json:"target_type"`
	Scope      string     `json:"scope,omitempty"`
	Authorized bool       `json:"authorized"`
	// AuthorizationMethod records how scope was granted: interactive
	// confirmation, the --authorized flag, environment, or simulation.
	AuthorizationMethod string `json:"authorization_method,omitempty"`

	ExecutionID string `json:"execution_id,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Operator    string `json:"operator,omitempty"`
	Simulated   bool   `json:"simulated,omitempty"`

	FramesTransmitted uint64 `json:"frames_transmitted,omitempty"`
	BytesTransmitted  uint64 `json:"bytes_transmitted,omitempty"`

	CleanupRequired bool         `json:"cleanup_required"`
	CleanupState    CleanupState `json:"cleanup_state,omitempty"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Duration   string    `json:"duration,omitempty"`

	Notes       []string   `json:"notes,omitempty"`
	Limitations []string   `json:"limitations,omitempty"`
	References  []string   `json:"references,omitempty"`
	Error       string     `json:"error,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	// Findings are what the operation concluded. They are carried in the record
	// so a replayed session shows findings next to the evidence supporting them.
	Findings []Finding `json:"findings,omitempty"`
}

// AddOperation appends an operation record, keeping the most recent run of a
// module so a repeated module does not silently grow the session.
func (s *Session) AddOperation(r OperationRecord) {
	for i := range s.Operations {
		if s.Operations[i].ID == r.ID {
			s.Operations[i] = r
			return
		}
	}
	s.Operations = append(s.Operations, r)
}

// OperationsByClass returns the records of one class in run order.
func (s *Session) OperationsByClass(class OperationClass) []OperationRecord {
	var out []OperationRecord
	for _, r := range s.Operations {
		if r.Class == class {
			out = append(out, r)
		}
	}
	return out
}
