package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// NewID creates a prefixed random identifier (8 hex bytes).
func NewID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

// Session holds the full state of one wireless assessment run.
type Session struct {
	ID           string                `json:"id"`
	TargetID     string                `json:"target_id"`
	Target       string                `json:"target"`
	Interface    string                `json:"interface,omitempty"`
	Profile      string                `json:"profile,omitempty"`
	Offline      bool                  `json:"offline"`
	Start        time.Time             `json:"start"`
	End          time.Time             `json:"end,omitempty"`
	Stages       []string              `json:"stages,omitempty"`
	Errors       []string              `json:"errors,omitempty"`
	Interfaces   []WirelessInterface   `json:"interfaces,omitempty"`
	AccessPoints []AccessPoint         `json:"access_points,omitempty"`
	Stations     []Station             `json:"stations,omitempty"`
	Observations []WirelessObservation `json:"observations,omitempty"`
	Traffic      []TrafficObservation  `json:"traffic,omitempty"`
	Findings     []Finding             `json:"findings,omitempty"`
	Evidence     []Evidence            `json:"evidence,omitempty"`
	RiskScore    int                   `json:"risk_score"`
	RiskLevel    string                `json:"risk_level"`
	OutputDir    string                `json:"output_dir,omitempty"`
	Attributes   map[string]string     `json:"attributes,omitempty"`
}

// NewSession creates a fresh session for a target.
func NewSession(t *Target) *Session {
	s := &Session{
		ID:         NewID("sess"),
		TargetID:   t.ID,
		Target:     t.DisplayName(),
		Profile:    t.Profile,
		Start:      time.Now().UTC(),
		Attributes: make(map[string]string),
	}
	if t.Interface != "" {
		s.Interface = t.Interface
	}
	return s
}

// Finish records the session end time.
func (s *Session) Finish() { s.End = time.Now().UTC() }

// AddFinding appends a finding, deduplicating by fingerprint.
func (s *Session) AddFinding(f Finding) {
	fp := f.Fingerprint()
	for i, existing := range s.Findings {
		if existing.Fingerprint() == fp {
			if f.Confidence.Value() > existing.Confidence.Value() {
				s.Findings[i].Confidence = f.Confidence
			}
			s.Findings[i].Evidence = mergeEvidence(s.Findings[i].Evidence, f.Evidence)
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

// AddEvidence appends evidence, deduplicating by hash.
func (s *Session) AddEvidence(e Evidence) {
	if e.Hash == "" {
		s.Evidence = append(s.Evidence, e)
		return
	}
	for _, existing := range s.Evidence {
		if existing.Hash == e.Hash {
			return
		}
	}
	s.Evidence = append(s.Evidence, e)
}

// AddObservation appends an observation, deduplicating by key.
func (s *Session) AddObservation(o WirelessObservation) {
	for _, existing := range s.Observations {
		if existing.Key == o.Key && existing.Target == o.Target && existing.Value == o.Value {
			return
		}
	}
	s.Observations = append(s.Observations, o)
}

func mergeEvidence(a, b []Evidence) []Evidence {
	seen := make(map[string]struct{}, len(a))
	var out []Evidence
	add := func(e Evidence) {
		k := string(e.Kind) + "@" + e.Source + "@" + e.Target + "@" + e.Detail
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		out = append(out, e)
	}
	for _, e := range a {
		add(e)
	}
	for _, e := range b {
		add(e)
	}
	return out
}

// SortedFindings returns findings ordered by severity desc, then rule.
func (s *Session) SortedFindings() []Finding {
	out := make([]Finding, len(s.Findings))
	copy(out, s.Findings)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity.Weight() != out[j].Severity.Weight() {
			return out[i].Severity.Weight() > out[j].Severity.Weight()
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
