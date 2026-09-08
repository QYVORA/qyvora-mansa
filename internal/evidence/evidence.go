// Package evidence provides evidence collection helpers.
package evidence

import (
	"crypto/sha256"
	"fmt"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// Collect adds an evidence item to a session, computing a hash if absent.
func Collect(sess *models.Session, kind models.EvidenceKind, source, target, detail string) {
	e := models.Evidence{
		ID:     models.NewID("ev"),
		Kind:   kind,
		Source: source,
		Target: target,
		Detail: detail,
	}
	if e.Hash == "" {
		h := sha256.Sum256([]byte(source + "\x00" + target + "\x00" + detail))
		e.Hash = fmt.Sprintf("%x", h)
	}
	sess.AddEvidence(e)
}
