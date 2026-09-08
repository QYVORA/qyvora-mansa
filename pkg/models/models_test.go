package models

import (
	"strings"
	"testing"
)

func TestNewIDFormat(t *testing.T) {
	id := NewID("sess")
	if !strings.HasPrefix(id, "sess-") {
		t.Errorf("NewID prefix missing: %q", id)
	}
	rest := strings.TrimPrefix(id, "sess-")
	if len(rest) != 16 {
		t.Errorf("expected 16 hex chars, got %q", rest)
	}
	if id2 := NewID("ev"); !strings.HasPrefix(id2, "ev-") {
		t.Errorf("NewID prefix handling broken: %q", id2)
	}
}

func TestBuildFindingIDDeterministic(t *testing.T) {
	a := BuildFindingID("WLAN-001", "open-network")
	b := BuildFindingID("WLAN-001", "open-network")
	if a != b {
		t.Errorf("finding ID not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "WLAN-") {
		t.Errorf("finding ID missing prefix: %q", a)
	}
	if BuildFindingID("WLAN-001", "open-network") == BuildFindingID("WLAN-002", "open-network") {
		t.Error("different rules should produce different IDs")
	}
}

func TestSeverityWeights(t *testing.T) {
	if SeverityCritical.Weight() != 4 || SeverityHigh.Weight() != 3 ||
		SeverityMedium.Weight() != 2 || SeverityLow.Weight() != 1 || SeverityInfo.Weight() != 0 {
		t.Error("severity weights out of order")
	}
}

func TestConfidenceValuesInRange(t *testing.T) {
	for name, c := range map[string]Confidence{
		"confirmed":    ConfConfirmed,
		"observed":     ConfObserved,
		"probable":     ConfProbable,
		"possible":     ConfPossible,
		"unknown":      ConfUnknown,
		"not observed": ConfNotObserved,
	} {
		v := c.Value()
		if v <= 0 || v > 1 {
			t.Errorf("confidence %s=%v out of range", name, v)
		}
	}
	if ConfConfirmed.Value() < ConfObserved.Value() {
		t.Error("confirmed must weight above observed")
	}
}

func TestScoreForBounds(t *testing.T) {
	sev := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	confs := []Confidence{ConfPossible, ConfObserved, ConfConfirmed}
	for _, s := range sev {
		for _, c := range confs {
			score := ScoreFor(Finding{Severity: s, Confidence: c})
			if score < 0 || score > 100 {
				t.Errorf("score %d out of range for %s/%s", score, s, c)
			}
		}
	}
	if ScoreFor(Finding{Severity: SeverityCritical, Confidence: ConfConfirmed}) != 84 {
		t.Error("critical/confirmed should score 84 (4 * 1.0 * 0.6 * 35)")
	}
}

func TestLevelFromScore(t *testing.T) {
	tests := []struct {
		score int
		want  RiskLevel
	}{
		{0, RiskNone}, {10, RiskLow}, {34, RiskLow},
		{35, RiskMedium}, {59, RiskMedium}, {60, RiskHigh},
		{79, RiskHigh}, {80, RiskCritical}, {100, RiskCritical},
	}
	for _, tt := range tests {
		if got := LevelFromScore(tt.score); got != tt.want {
			t.Errorf("LevelFromScore(%d)=%q want %q", tt.score, got, tt.want)
		}
	}
}

func TestAggregateRiskEmpty(t *testing.T) {
	if AggregateRisk(nil) != 0 {
		t.Error("empty findings should score 0")
	}
}

func TestDisplayName(t *testing.T) {
	target := &Target{Type: TargetInterface, Value: "wlan0"}
	if got := target.DisplayName(); got != "interface:wlan0" {
		t.Errorf("DisplayName=%q", got)
	}
	if (&Target{Type: TargetBSSID}).DisplayName() != "bssid:all" {
		t.Error("empty value should render :all")
	}
	if (&Target{}).DisplayName() != ":all" {
		t.Error("empty type should still render")
	}
	if (*Target)(nil).DisplayName() != "" {
		t.Error("nil target should render empty")
	}
}

func TestTargetAuthorized(t *testing.T) {
	if (&Target{Authorization: Authorization{Granted: true}}).Authorized() == false {
		t.Error("granted target must report authorized")
	}
	if (&Target{}).Authorized() {
		t.Error("ungranted target must not report authorized")
	}
}

func TestNewSession(t *testing.T) {
	target := &Target{Type: TargetInterface, Value: "wlan0", Interface: "wlan0"}
	s := NewSession(target)
	if s.ID == "" {
		t.Error("session missing ID")
	}
	if s.Target != "interface:wlan0" || s.Interface != "wlan0" {
		t.Errorf("session fields: %+v", s)
	}
	if s.Attributes == nil {
		t.Error("session Attributes must be initialized")
	}
	if s.RiskLevel != "" || s.RiskScore != 0 {
		t.Error("fresh session must start risk-free")
	}
}

func TestAddFindingDeduplicatesAndUpgrades(t *testing.T) {
	s := NewSession(&Target{Type: TargetInterface, Value: "wlan0"})
	base := Finding{RuleID: "WLAN-001", Category: "open-network", Title: "x",
		Severity: SeverityHigh, Confidence: ConfObserved,
		Evidence: []Evidence{{Kind: EvidenceConfig, Source: "scan"}}}
	s.AddFinding(base)
	s.AddFinding(base)
	if len(s.Findings) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d", len(s.Findings))
	}
	upgraded := base
	upgraded.Confidence = ConfConfirmed
	s.AddFinding(upgraded)
	if len(s.Findings) != 1 {
		t.Fatalf("expected still 1 finding, got %d", len(s.Findings))
	}
	if s.Findings[0].Confidence != ConfConfirmed {
		t.Error("confidence should have upgraded to confirmed")
	}
}

func TestAddEvidenceDedupByHash(t *testing.T) {
	s := NewSession(&Target{Type: TargetInterface, Value: "wlan0"})
	s.AddEvidence(Evidence{ID: "e1", Hash: "abc"})
	s.AddEvidence(Evidence{ID: "e2", Hash: "abc"})
	if len(s.Evidence) != 1 {
		t.Errorf("expected 1 evidence, got %d", len(s.Evidence))
	}
	s.AddEvidence(Evidence{ID: "e3"})
	if len(s.Evidence) != 2 {
		t.Errorf("evidenceless entries should be append-only, got %d", len(s.Evidence))
	}
}

func TestAddObservationDedups(t *testing.T) {
	s := NewSession(&Target{Type: TargetInterface, Value: "wlan0"})
	o := WirelessObservation{Key: "mode", Target: "wlan0", Value: "monitor"}
	s.AddObservation(o)
	s.AddObservation(o)
	if len(s.Observations) != 1 {
		t.Errorf("expected 1 observation, got %d", len(s.Observations))
	}
}

func TestSortedFindingsOrdering(t *testing.T) {
	s := NewSession(&Target{Type: TargetInterface, Value: "wlan0"})
	s.AddFinding(Finding{RuleID: "WLAN-002", Category: "a", Title: "low", Severity: SeverityLow})
	s.AddFinding(Finding{RuleID: "WLAN-001", Category: "b", Title: "high", Severity: SeverityHigh})
	got := s.SortedFindings()
	if got[0].Severity != SeverityHigh {
		t.Error("high severity must sort first")
	}
}

func TestRiskLevelRequiresConfirmation(t *testing.T) {
	if !RiskHigh.RequiresConfirmation() || !RiskCritical.RequiresConfirmation() {
		t.Error("high/critical must require confirmation")
	}
	if RiskLow.RequiresConfirmation() || RiskMedium.RequiresConfirmation() || RiskNone.RequiresConfirmation() {
		t.Error("low/medium/none must not require confirmation")
	}
}

func TestFindingFingerprintIgnoresEvidenceOrder(t *testing.T) {
	a := Finding{RuleID: "R1", Category: "c", Title: "t", Evidence: []Evidence{{Kind: "k1", Source: "s1"}, {Kind: "k2", Source: "s2"}}}
	b := Finding{RuleID: "R1", Category: "c", Title: "t", Evidence: []Evidence{{Kind: "k2", Source: "s2"}, {Kind: "k1", Source: "s1"}}}
	if a.Fingerprint() != b.Fingerprint() {
		t.Error("fingerprint must be order-independent")
	}
}
