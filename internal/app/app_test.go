package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func newTestApp(t *testing.T) *AppState {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("QYVORA_MANSA_SESSION_DIR", dir)
	t.Setenv("QYVORA_MANSA_TARGET_STATE", filepath.Join(dir, "targets.json"))
	a := New("")
	if a.InitErr != nil {
		t.Fatalf("app init: %v", a.InitErr)
	}
	a.Init("", "", true, false, false)
	return a
}

func TestAppRunPipelineSim(t *testing.T) {
	a := newTestApp(t)
	sess, err := a.RunPipeline(context.Background(),
		&models.Target{Type: models.TargetInterface, Value: "wlan0", Interface: "wlan0"}, true)
	if err != nil {
		t.Fatalf("run pipeline: %v", err)
	}
	if sess == nil {
		t.Fatal("nil session")
	}
	if len(sess.AccessPoints) != 16 {
		t.Errorf("APs = %d, want 16", len(sess.AccessPoints))
	}
	if len(sess.Findings) == 0 {
		t.Error("expected findings")
	}
	if sess.RiskScore <= 0 {
		t.Errorf("risk score = %d", sess.RiskScore)
	}
	// Session must be persisted to the configured store.
	path := filepath.Join(a.Store.Dir(), sess.ID+".session.json")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("session not persisted: %v", err)
	}
}

func TestAppAnalyzeSessionNoRescan(t *testing.T) {
	a := newTestApp(t)
	sess, err := a.RunPipeline(context.Background(),
		&models.Target{Type: models.TargetInterface, Value: "wlan0", Interface: "wlan0"}, true)
	if err != nil {
		t.Fatalf("run pipeline: %v", err)
	}
	before := len(sess.AccessPoints)

	// Add a finding to prove results are appended, not clobbered.
	analyzed, err := a.AnalyzeSession(context.Background(), sess)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(analyzed.AccessPoints) != before {
		t.Errorf("re-analysis resccanned: APs %d -> %d", before, len(analyzed.AccessPoints))
	}
	if len(analyzed.Findings) == 0 {
		t.Error("analyzed session missing findings")
	}
	if analyzed.RiskScore <= 0 {
		t.Errorf("analyzed session risk score = %d", analyzed.RiskScore)
	}
	// Last stage must be risk, not a collection stage.
	if len(analyzed.Stages) == 0 || analyzed.Stages[len(analyzed.Stages)-1] != "risk" {
		t.Errorf("stages tail = %v", analyzed.Stages)
	}
}
