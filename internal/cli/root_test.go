package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/app"
	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
)

func resetTestApp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("QYVORA_MANSA_SESSION_DIR", dir)
	t.Setenv("QYVORA_MANSA_TARGET_STATE", filepath.Join(dir, "targets.json"))
	appState = app.New("")
}

func TestExecuteArgsVersion(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"version", "-o", "json"}); got != exitcode.Success {
		t.Errorf("version exit code = %d", got)
	}
}

func TestExecuteArgsUnknownCommandIsUsage(t *testing.T) {
	if got := ExecuteArgs(context.Background(), []string{"bogus"}); got != exitcode.Usage {
		t.Errorf("unknown command exit code = %d, want %d", got, exitcode.Usage)
	}
}

func TestExecuteArgsAssessSim(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"assess", "--sim", "-o", "json"}); got != exitcode.Success {
		t.Errorf("assess exit code = %d", got)
	}
	// The app state should now own a session store with artifacts.
	entries, err := os.ReadDir(appState.Store.Dir())
	if err != nil {
		t.Fatalf("read session dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("assess --sim should persist a session")
	}
}

func TestExecuteArgsMissingSessionIsRuntime(t *testing.T) {
	resetTestApp(t)
	dir := t.TempDir()
	t.Setenv("QYVORA_MANSA_SESSION_DIR", dir)
	if got := ExecuteArgs(context.Background(), []string{"findings", "-o", "json"}); got == exitcode.Success {
		t.Error("findings with no session should fail")
	}
}
