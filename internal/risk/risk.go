// Package risk provides the Mansa risk scoring model.
// Scores are transparent: severity × confidence × exposure heuristic / max.
package risk

import (
	"context"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Assessor computes aggregate risk for a set of findings.
type Assessor struct{}

// Assess returns the average per-finding risk score and its level string.
func (a *Assessor) Assess(_ context.Context, findings []models.Finding) (int, string) {
	if len(findings) == 0 {
		return 0, "none"
	}
	total := 0
	for _, f := range findings {
		total += models.ScoreFor(f)
	}
	avg := total / len(findings)
	return avg, string(models.LevelFromScore(avg))
}
