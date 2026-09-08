package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	v, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v.GetBool("authorized") {
		t.Error("authorized default must be false")
	}
	if v.GetInt("wireless.timeout_seconds") != 30 {
		t.Error("wireless.timeout_seconds default must be 30")
	}
	if v.GetString("output") != "terminal" {
		t.Error("output default must be terminal")
	}
	if v.GetString("analysis.confidence_threshold") != "medium" {
		t.Error("confidence threshold default must be medium")
	}
	if Timeout(v) != 30*time.Second {
		t.Errorf("Timeout default = %v", Timeout(v))
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "wireless:\n  interface: wlan1\n  timeout_seconds: 15\noutput: json\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	v, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if v.GetString("wireless.interface") != "wlan1" {
		t.Errorf("interface = %q want wlan1", v.GetString("wireless.interface"))
	}
	if v.GetInt("wireless.timeout_seconds") != 15 {
		t.Errorf("timeout = %v want 15", v.GetInt("wireless.timeout_seconds"))
	}
	if v.GetString("output") != "json" {
		t.Errorf("output = %q want json", v.GetString("output"))
	}
	// Unset values still fall back to defaults.
	if !v.GetBool("verbose") {
		t.Log("verbose default stays false")
	}
}

func TestLoadMalformedFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(": : bad yaml :: ["), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("malformed config must produce an error")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("QYVORA_MANSA_WIRELESS_TIMEOUT_SECONDS", "9")
	v, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := v.GetInt("wireless.timeout_seconds"); got != 9 {
		t.Errorf("env override timeout = %d want 9", got)
	}
}
