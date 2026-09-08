package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	sess := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0", Interface: "wlan0"})
	sess.AccessPoints = []models.AccessPoint{{BSSID: "02:00:00:00:00:01", SSID: "TestNet", Channel: 6, Band: "2.4GHz"}}
	sess.Finish()

	path, err := store.Save(sess)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if filepath.Base(path) != sess.ID+".session.json" {
		t.Errorf("unexpected file name: %s", path)
	}

	loaded, err := store.Load(sess.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.ID != sess.ID || len(loaded.AccessPoints) != 1 || loaded.Interface != "wlan0" {
		t.Errorf("round trip mismatch: %+v", loaded)
	}
}

func TestStoreLoadByPath(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	sess := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0"})
	path, err := store.Save(sess)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := store.Load(path); err != nil {
		t.Errorf("load by path: %v", err)
	}
}

func TestStoreLatest(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)
	first := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0"})
	if _, err := store.Save(first); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Ensure distinct mtimes so ordering is deterministic.
	second := models.NewSession(&models.Target{Type: models.TargetInterface, Value: "wlan0"})
	path2, _ := store.Save(second)
	_ = os.Chtimes(path2, second.Start, second.Start.Add(1))

	latest, err := store.Latest()
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.ID != second.ID {
		t.Errorf("latest = %s want %s", latest.ID, second.ID)
	}
}

func TestStoreListEmpty(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.List(); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := store.Latest(); err == nil {
		t.Error("latest on empty store should error")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := NewStore(t.TempDir()).Load("does-not-exist"); err == nil {
		t.Error("loading a missing session should error")
	}
}
