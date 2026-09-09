package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/transport"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func TestRunPipelineSim(t *testing.T) {
	runner := &Runner{}
	target := &models.Target{Type: models.TargetInterface, Value: "wlan0", Interface: "wlan0"}
	sess := models.NewSession(target)
	reported := false
	env := &Env{
		Backend: transport.New(),
		Session: sess,
		Offline: true,
		ReportFn: func(_ context.Context, _ *models.Session) error {
			reported = true
			return nil
		},
	}
	if err := runner.Run(context.Background(), env); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sess.Stages) != len(StageOrder) {
		t.Fatalf("stages = %v want all 8", sess.Stages)
	}
	for i, want := range StageOrder {
		if sess.Stages[i] != want {
			t.Errorf("stage[%d]=%q want %q", i, sess.Stages[i], want)
		}
	}
	if len(sess.AccessPoints) != 23 {
		t.Errorf("discovered %d APs, want 23", len(sess.AccessPoints))
	}
	if len(sess.Findings) == 0 {
		t.Error("expected findings on the simulation dataset")
	}
	if sess.RiskScore <= 0 {
		t.Errorf("expected positive risk score, got %d", sess.RiskScore)
	}
	if sess.RiskLevel == "" {
		t.Error("expected risk level")
	}
	if !reported {
		t.Error("ReportFn must be called at the report stage")
	}
	if sess.End.IsZero() {
		t.Error("session must be finished")
	}
}

func TestRunUntilStops(t *testing.T) {
	runner := &Runner{}
	sess := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0"})
	env := &Env{Backend: transport.New(), Session: sess, Offline: true}
	if err := runner.RunUntil(context.Background(), env, StageEnumerate); err != nil {
		t.Fatalf("run until enumerate: %v", err)
	}
	want := []string{StageDiscover, StageEnumerate}
	if len(sess.Stages) != len(want) {
		t.Fatalf("stages = %v want %v", sess.Stages, want)
	}
	if len(sess.Findings) != 0 {
		t.Error("no findings expected before analyze stage")
	}
}

func TestRunUnknownStage(t *testing.T) {
	runner := &Runner{}
	sess := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0"})
	env := &Env{Backend: transport.New(), Session: sess, Offline: true}
	if err := runner.RunUntil(context.Background(), env, "bogus"); err == nil {
		t.Error("unknown stage must error")
	} else if !strings.Contains(err.Error(), "unknown pipeline stage") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunStagesReanalysis(t *testing.T) {
	runner := &Runner{}
	sess := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0"})
	// Simulate a session whose collection stages already ran.
	sess.AccessPoints = []models.AccessPoint{{
		BSSID: "02:00:00:00:00:01", SSID: "Free_WiFi", Channel: 1, Band: "2.4GHz",
		Security: models.SecurityAdvertisement{Enabled: false},
	}}
	env := &Env{Backend: transport.New(), Session: sess, Offline: true}
	if err := runner.RunStages(context.Background(), env, []string{StageAnalyze, StageValidate, StageFindings, StageRisk}); err != nil {
		t.Fatalf("run stages: %v", err)
	}
	if len(sess.AccessPoints) != 1 {
		t.Errorf("re-analysis must not re-scan; got %d APs", len(sess.AccessPoints))
	}
	if len(sess.Findings) == 0 {
		t.Error("expected findings from re-analysis")
	}
	got := strings.Join(sess.Stages, ",")
	if got != StageAnalyze+","+StageValidate+","+StageFindings+","+StageRisk {
		t.Errorf("stages = %q", got)
	}
}
