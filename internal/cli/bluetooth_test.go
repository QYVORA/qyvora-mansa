package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/exitcode"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func TestBluetoothParseAdvertisementAcceptsFixture(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "parse-advertisement", "03030f18", "-o", "json"}); got != exitcode.Success {
		t.Fatalf("parse advertisement exit code = %d", got)
	}
}

func TestBluetoothScanSimulationPersistsEvidence(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "scan", "--sim", "-o", "json"}); got != exitcode.Success {
		t.Fatalf("simulated BLE scan exit code = %d", got)
	}
	session, err := appState.LatestSession()
	if err != nil {
		t.Fatal(err)
	}
	if !session.Simulated || len(session.BluetoothDevices) != 1 || len(session.Evidence) != 1 || !session.Authorization.Granted {
		t.Fatalf("simulated BLE scan session missing observations/evidence/authorization: %+v", session)
	}
}

func TestBluetoothLiveScanRequiresExplicitAuthorization(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "scan", "--adapter", "hci0", "--duration", "1s"}); got != exitcode.AuthorizationRefused {
		t.Fatalf("unauthorized live BLE scan exit code = %d", got)
	}
}

func TestNewBluetoothSessionRetainsTargetScope(t *testing.T) {
	target := &models.Target{ID: "target-1", Type: models.TargetBluetoothAdapter, Value: "hci0", Authorization: models.Authorization{Granted: true, Scope: "owned lab adapter"}}
	session := models.NewSession(target)
	if session.Authorization.Scope != target.Authorization.Scope {
		t.Fatalf("session authorization=%+v", session.Authorization)
	}
}

func TestBluetoothParserSimulationCommands(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "parse-advertisement", "--sim", "-o", "json"}); got != exitcode.Success {
		t.Fatalf("simulated advertisement parse exit code = %d", got)
	}
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "parse-hci-event", "--sim", "-o", "json"}); got != exitcode.Success {
		t.Fatalf("simulated HCI parse exit code = %d", got)
	}
}

func TestBluetoothAdaptersCommand(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "adapters", "-o", "json"}); got != exitcode.Success {
		t.Fatalf("Bluetooth adapters exit code = %d", got)
	}
}

func TestBluetoothParseHCIEventCommand(t *testing.T) {
	resetTestApp(t)
	packet := "043e10020100000605040302010403030f18d6"
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "parse-hci-event", packet, "-o", "json"}); got != exitcode.Success {
		t.Fatalf("parse HCI event exit code = %d", got)
	}
}

func TestBluetoothAnalyzeGATTReadsBoundedFixture(t *testing.T) {
	resetTestApp(t)
	path := filepath.Join(t.TempDir(), "gatt.json")
	data := `{"device_address":"AA:BB:CC:DD:EE:FF","services":[{"uuid":"180F","characteristics":[{"uuid":"2A19","handle":42,"properties":["write_without_response"]}]}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "analyze-gatt", path, "-o", "json"}); got != exitcode.Success {
		t.Fatalf("analyze GATT exit code = %d", got)
	}
}

func TestBluetoothAnalyzeGATTSimulation(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "analyze-gatt", "--sim", "-o", "json"}); got != exitcode.Success {
		t.Fatalf("simulated GATT analysis exit code = %d", got)
	}
}

func TestBluetoothParseAdvertisementRejectsInvalidHex(t *testing.T) {
	resetTestApp(t)
	if got := ExecuteArgs(context.Background(), []string{"bluetooth", "parse-advertisement", "0xz1"}); got != exitcode.Usage {
		t.Fatalf("invalid hex exit code = %d, want usage", got)
	}
}
