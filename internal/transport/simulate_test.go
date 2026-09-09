package transport

import (
	"context"
	"testing"
)

func TestSimBackendDeterministic(t *testing.T) {
	b := New()
	aps1, st1, err := b.Scan(context.Background(), "wlan0", 0)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	aps2, st2, _ := b.Scan(context.Background(), "wlan0", 0)
	if len(aps1) != len(aps2) || len(st1) != len(st2) {
		t.Fatalf("nondeterministic scan: %d/%d APs, %d/%d stations",
			len(aps1), len(aps2), len(st1), len(st2))
	}
	for i := range aps1 {
		if aps1[i].BSSID != aps2[i].BSSID || aps1[i].SSID != aps2[i].SSID ||
			aps1[i].Channel != aps2[i].Channel || aps1[i].Security.Cipher != aps2[i].Security.Cipher {
			t.Errorf("AP %d differs between runs: %+v vs %+v", i, aps1[i], aps2[i])
		}
	}
}

func TestSimBackendFixture(t *testing.T) {
	b := New()
	if b.Name() != "simulation" {
		t.Errorf("backend name = %q", b.Name())
	}
	if !b.Supported() {
		t.Error("sim backend must report supported")
	}
	interfaces, err := b.DiscoverInterfaces()
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(interfaces) != 2 {
		t.Errorf("expected 2 interfaces, got %d", len(interfaces))
	}
	aps, stations, err := b.Scan(context.Background(), "wlan0", 0)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(aps) != 23 {
		t.Errorf("expected 23 access points, got %d", len(aps))
	}
	if len(stations) != 7 {
		t.Errorf("expected 7 stations, got %d", len(stations))
	}
	// The dataset must exercise every security rule.
	seen := map[string]bool{}
	hidden := 0
	transition := 0
	for _, ap := range aps {
		for _, p := range ap.Security.Protocols {
			switch p {
			case "WEP", "WPA", "WPA2", "WPA3":
				seen[p] = true
			}
		}
		if ap.Security.WPS {
			seen["WPS"] = true
		}
		if ap.Hidden || ap.SSID == "" {
			hidden++
		}
		if ap.Security.Transition {
			transition++
		}
	}
	for _, want := range []string{"WEP", "WPA", "WPA2", "WPA3", "WPS"} {
		if !seen[want] {
			t.Errorf("fixture missing %s coverage", want)
		}
	}
	if hidden == 0 {
		t.Error("fixture must include a hidden-SSID AP")
	}
	if transition == 0 {
		t.Error("fixture must include a WPA3-transition AP")
	}
	// Deterministic interface set.
	if interfaces[0].Name != "wlan0" {
		t.Errorf("unexpected first interface: %+v", interfaces[0])
	}
	traffic, err := b.Observe(context.Background(), "wlan0")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(traffic) == 0 {
		t.Error("fixture must supply traffic observations")
	}
	for _, tr := range traffic {
		if tr.Target == "" {
			t.Errorf("traffic observation missing target: %+v", tr)
		}
	}
}

func TestSimBackendCapabilities(t *testing.T) {
	if caps := New().Capabilities(); len(caps) == 0 {
		t.Error("sim backend must expose capabilities")
	}
}
