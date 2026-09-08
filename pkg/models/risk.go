package models

// RiskLevel represents aggregate risk classification.
type RiskLevel string

const (
	RiskNone     RiskLevel = "none"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// RequiresConfirmation reports whether operations at this risk level
// need an interactive confirmation prompt.
func (r RiskLevel) RequiresConfirmation() bool {
	return r == RiskHigh || r == RiskCritical
}

// RiskScoreFor computes a per-finding risk score 0..100.
type RiskScoreFor func(f Finding) int

// ScoreFor returns a risk score for one finding based on severity,
// confidence, and exposure heuristic.
func ScoreFor(f Finding) int {
	sev := float64(f.Severity.Weight())
	conf := f.Confidence.Value()
	exposure := 3.0
	score := int(sev * conf * (exposure / 5.0) * 35.0)
	if score > 100 {
		score = 100
	}
	return score
}

// AggregateRisk computes the average per-finding risk score.
func AggregateRisk(findings []Finding) int {
	if len(findings) == 0 {
		return 0
	}
	total := 0
	for _, f := range findings {
		total += ScoreFor(f)
	}
	return total / len(findings)
}

// LevelFromScore maps a numeric score to a risk level string.
func LevelFromScore(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 60:
		return RiskHigh
	case score >= 35:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}
