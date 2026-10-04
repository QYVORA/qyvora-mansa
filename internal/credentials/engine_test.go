package credentials

import (
	"context"
	"errors"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type verifierFunc func(context.Context, *models.Target, string) (Verification, error)

func (f verifierFunc) Verify(c context.Context, t *models.Target, v string) (Verification, error) {
	return f(c, t, v)
}
func authorizedTarget() *models.Target {
	return &models.Target{Type: models.TargetBSSID, Value: "02:00:00:00:00:01", Authorization: models.Authorization{Granted: true, GrantedAt: time.Now()}}
}
func TestRunStreamsCandidatesAndOnlyReturnsEvidenceBackedMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.txt")
	if e := os.WriteFile(path, []byte("alpha\nbeta\n"), 0600); e != nil {
		t.Fatal(e)
	}
	var checked []string
	result, e := Run(context.Background(), authorizedTarget(), Config{Wordlists: []string{path}, Generated: []string{"gamma"}, Mutations: []Mutation{{Suffix: "!"}}, MaxCandidates: 8}, verifierFunc(func(_ context.Context, _ *models.Target, value string) (Verification, error) {
		checked = append(checked, value)
		return Verification{Matched: value == "beta!", Evidence: []string{"protocol success response"}}, nil
	}), nil)
	if e != nil {
		t.Fatal(e)
	}
	if result == nil || !result.Verified || len(result.Evidence) != 1 || result.CandidateSHA256 == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !reflect.DeepEqual(checked, []string{"alpha", "alpha!", "beta", "beta!"}) {
		t.Fatalf("candidate order: %v", checked)
	}
}
func TestRunRequiresAuthorizationVerifierAndEvidence(t *testing.T) {
	cfg := Config{Generated: []string{"candidate"}, MaxCandidates: 1}
	v := verifierFunc(func(context.Context, *models.Target, string) (Verification, error) {
		return Verification{Matched: true}, nil
	})
	if _, e := Run(context.Background(), &models.Target{}, cfg, v, nil); e == nil {
		t.Fatal("unauthorized target accepted")
	}
	if _, e := Run(context.Background(), authorizedTarget(), cfg, nil, nil); e == nil {
		t.Fatal("missing verifier accepted")
	}
	if _, e := Run(context.Background(), authorizedTarget(), cfg, v, nil); e == nil {
		t.Fatal("match without evidence accepted")
	}
}
func TestRunCandidateLimitAndCancellation(t *testing.T) {
	cfg := Config{Generated: []string{"one", "two"}, MaxCandidates: 1}
	v := verifierFunc(func(context.Context, *models.Target, string) (Verification, error) { return Verification{}, nil })
	if _, e := Run(context.Background(), authorizedTarget(), cfg, v, nil); !errors.Is(e, ErrCandidateLimit) {
		t.Fatalf("expected limit error, got %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Run(ctx, authorizedTarget(), Config{Generated: []string{"one"}, MaxCandidates: 1}, v, nil); !errors.Is(e, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", e)
	}
}
