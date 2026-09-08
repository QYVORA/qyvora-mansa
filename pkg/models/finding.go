package models

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity levels ordered by impact.
type Severity string

const (
	SeverityInfo     Severity = "informational"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Weights maps severity to a numeric weight for scoring.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Confidence reflects how sure Mansa is about a finding.
type Confidence string

const (
	ConfConfirmed   Confidence = "confirmed"
	ConfObserved    Confidence = "observed"
	ConfProbable    Confidence = "probable"
	ConfPossible    Confidence = "possible"
	ConfUnknown     Confidence = "unknown"
	ConfNotObserved Confidence = "not_observed"
)

// ConfidenceValue returns a numeric weight 0..1 for scoring.
func (c Confidence) Value() float64 {
	switch c {
	case ConfConfirmed:
		return 1.0
	case ConfObserved:
		return 0.9
	case ConfProbable:
		return 0.7
	case ConfPossible:
		return 0.5
	case ConfUnknown:
		return 0.3
	case ConfNotObserved:
		return 0.1
	default:
		return 0.5
	}
}

// EvidenceKind classifies the type of supporting data.
type EvidenceKind string

const (
	EvidenceObservation EvidenceKind = "observation"
	EvidenceConfig      EvidenceKind = "configuration"
	EvidenceSignal      EvidenceKind = "signal"
	EvidenceProtocol    EvidenceKind = "protocol"
	EvidenceChannel     EvidenceKind = "channel"
	EvidenceVendor      EvidenceKind = "vendor"
)

// Evidence is first-class supporting data traceable to an observation.
type Evidence struct {
	ID     string       `json:"id"`
	Kind   EvidenceKind `json:"kind"`
	Source string       `json:"source"`
	Target string       `json:"target,omitempty"`
	Detail string       `json:"detail,omitempty"`
	Hash   string       `json:"hash,omitempty"`
}

// FindingStatus tracks the lifecycle of a finding.
type FindingStatus string

const (
	FindingDetected      FindingStatus = "detected"
	FindingConfirmed     FindingStatus = "confirmed"
	FindingFalsePositive FindingStatus = "false-positive"
	FindingResolved      FindingStatus = "resolved"
	FindingInformational FindingStatus = "informational"
)

// Finding is one evidence-backed security observation.
type Finding struct {
	ID             string        `json:"id"`
	RuleID         string        `json:"rule_id"`
	Title          string        `json:"title"`
	Category       string        `json:"category"`
	Severity       Severity      `json:"severity"`
	Confidence     Confidence    `json:"confidence"`
	Description    string        `json:"description"`
	Target         string        `json:"target"`
	Status         FindingStatus `json:"status"`
	Recommendation string        `json:"recommendation,omitempty"`
	Evidence       []Evidence    `json:"evidence,omitempty"`
	References     []string      `json:"references,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
}

// Fingerprint returns a deterministic content hash for deduplication.
func (f Finding) Fingerprint() string {
	keys := make([]string, 0, len(f.Evidence))
	for _, e := range f.Evidence {
		keys = append(keys, string(e.Kind)+"@"+e.Source)
	}
	sort.Strings(keys)
	h := sha256.Sum256([]byte(strings.Join([]string{
		f.RuleID, f.Category, f.Title, strings.Join(keys, "|"),
	}, "\x00")))
	return fmt.Sprintf("%x", h)
}

// BuildFindingID creates a deterministic rule-based finding identifier.
func BuildFindingID(ruleID, category string) string {
	prefix := strings.ToUpper(strings.ReplaceAll(category, "-", ""))
	if len(prefix) > 6 {
		prefix = prefix[:6]
	}
	h := sha256.Sum256([]byte(ruleID))
	return fmt.Sprintf("WLAN-%s-%X", prefix, h[:4])
}
