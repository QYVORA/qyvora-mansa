// Package findings provides finding deduplication and confidence escalation.
package findings

import (
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Dedupe removes duplicate findings (by fingerprint), keeping the
// highest-confidence version and merging evidence.
func Dedupe(all []models.Finding) []models.Finding {
	byFP := make(map[string]int) // fingerprint → index in result
	var result []models.Finding
	for _, f := range all {
		fp := f.Fingerprint()
		if idx, ok := byFP[fp]; ok {
			if f.Confidence.Value() > result[idx].Confidence.Value() {
				result[idx].Confidence = f.Confidence
			}
			result[idx].Evidence = mergeEvidence(result[idx].Evidence, f.Evidence)
			continue
		}
		byFP[fp] = len(result)
		result = append(result, f)
	}
	return result
}

func mergeEvidence(a, b []models.Evidence) []models.Evidence {
	seen := make(map[string]struct{}, len(a))
	for _, e := range a {
		if e.Hash != "" {
			seen[e.Hash] = struct{}{}
		}
	}
	for _, e := range b {
		if e.Hash == "" {
			a = append(a, e)
		} else if _, ok := seen[e.Hash]; !ok {
			a = append(a, e)
			seen[e.Hash] = struct{}{}
		}
	}
	return a
}
