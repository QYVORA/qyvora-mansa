// Package validation provides a confidence escalation pass that can
// promote findings to "observed" when corroborating evidence exists.
package validation

import "github.com/QYVORA/qyvora-mansa/pkg/models"

// Result captures what validation changed.
type Result struct {
	Upgraded     int      `json:"upgraded"`
	Corroborated []string `json:"corroborated_ids,omitempty"`
}

// Validate escalates findings whose confidence is below "observed" when
// the finding carries at least two pieces of evidence.
func Validate(findings []models.Finding) Result {
	var r Result
	for i := range findings {
		if findings[i].Confidence.Value() >= models.ConfObserved.Value() {
			continue
		}
		if len(findings[i].Evidence) >= 2 {
			findings[i].Confidence = models.ConfObserved
			r.Upgraded++
			r.Corroborated = append(r.Corroborated, findings[i].ID)
		}
	}
	return r
}
