package builtin

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/rules"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func testAP(bssid, ssid string, ch int, band string, sig int, sec models.SecurityAdvertisement) models.AccessPoint {
	now := time.Now().UTC()
	return models.AccessPoint{
		BSSID:       bssid,
		SSID:        ssid,
		Channel:     ch,
		Band:        band,
		Signal:      sig,
		Security:    sec,
		FirstSeen:   now,
		LastSeen:    now,
		IsSimulated: true,
	}
}

func runAllRules(t *testing.T, aps []models.AccessPoint) []models.Finding {
	t.Helper()
	return runAllRulesFull(t, aps, nil, nil)
}

func runAllRulesFull(t *testing.T, aps []models.AccessPoint, sts []models.Station, tr []models.TrafficObservation) []models.Finding {
	t.Helper()
	ctx := &rules.Context{APs: aps, Stations: sts, Traffic: tr}
	var all []models.Finding
	for _, r := range All() {
		for _, f := range r.Detect(ctx) {
			f.RuleID = r.ID
			all = append(all, f)
		}
	}
	return all
}

func findingsByRule(t *testing.T, aps []models.AccessPoint) map[string]int {
	t.Helper()
	got := map[string]int{}
	for _, f := range runAllRules(t, aps) {
		got[f.RuleID]++
	}
	return got
}

func assertRule(t *testing.T, got map[string]int, rule string, want int) {
	t.Helper()
	if got[rule] != want {
		t.Errorf("rule %s: got %d findings, want %d", rule, got[rule], want)
	}
}

func TestWPA1RuleDoesNotMatchWPA2(t *testing.T) {
	aps := []models.AccessPoint{
		testAP("02:00:00:00:00:01", "HomeOffice_WiFi", 6, "2.4GHz", -45,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2", "TKIP"}, Cipher: "TKIP", KeyMgmt: "PSK"}),
		testAP("02:00:00:00:00:02", "OldRouter", 11, "2.4GHz", -60,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA", "TKIP"}, Cipher: "TKIP", KeyMgmt: "PSK"}),
	}
	got := findingsByRule(t, aps)
	assertRule(t, got, "WLAN-003", 1)
	assertRule(t, got, "WLAN-004", 1)
}

func TestAllBuiltinRulesFire(t *testing.T) {
	aps := []models.AccessPoint{
		// WLAN-001/006: open, no protocols
		testAP("02:00:00:00:00:01", "Free_WiFi", 1, "2.4GHz", -50,
			models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"}),
		// WLAN-002: WEP
		testAP("02:00:00:00:00:02", "Old_WEP", 3, "2.4GHz", -55,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WEP"}, Cipher: "WEP", Auth: "OPEN"}),
		// WLAN-003: WPA1-TKIP
		testAP("02:00:00:00:00:03", "Legacy_WPA", 5, "2.4GHz", -60,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA", "TKIP"}, Cipher: "TKIP", KeyMgmt: "PSK"}),
		// WLAN-004: WPA2-TKIP
		testAP("02:00:00:00:00:04", "HomeOffice_WiFi", 6, "2.4GHz", -45,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2", "TKIP"}, Cipher: "TKIP", KeyMgmt: "PSK"}),
		// WLAN-005: WPS
		testAP("02:00:00:00:00:05", "Guest_Net", 10, "2.4GHz", -58,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK", WPS: true}),
		// WLAN-010: crowded channel (4 APs share ch 1)
		testAP("02:00:00:00:00:06", "Crowd_A", 1, "2.4GHz", -70,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
		testAP("02:00:00:00:00:07", "Crowd_B", 1, "2.4GHz", -71,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
		testAP("02:00:00:00:00:08", "Crowd_C", 1, "2.4GHz", -72,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
		testAP("02:00:00:00:00:09", "Crowd_D", 1, "2.4GHz", -73,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
		// WLAN-011: overlapping channels 6 & 7 on 2.4 GHz
		testAP("02:00:00:00:00:0A", "Overlap_A", 6, "2.4GHz", -65,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
		testAP("02:00:00:00:00:0B", "Overlap_B", 7, "2.4GHz", -66,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
		// WLAN-012: dense 6 GHz (5 APs)
		testAP("02:00:00:00:00:C1", "6G_1", 9, "6GHz", -40, sec6G),
		testAP("02:00:00:00:00:C2", "6G_2", 37, "6GHz", -41, sec6G),
		testAP("02:00:00:00:00:C3", "6G_3", 61, "6GHz", -42, sec6G),
		testAP("02:00:00:00:00:C4", "6G_4", 85, "6GHz", -43, sec6G),
		testAP("02:00:00:00:00:C5", "6G_5", 113, "6GHz", -44, sec6G),
		// WLAN-020: very strong signal (>-20)
		testAP("02:00:00:00:00:10", "Nearby_Router", 11, "2.4GHz", -12,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP", KeyMgmt: "PSK"}),
		// WLAN-030: legacy protocol capability
		testAP("02:00:00:00:00:11", "Legacy_Caps", 9, "2.4GHz", -80,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, Cipher: "CCMP"}),
	}
	aps[17].Capabilities = "802.11b/g/n,HT20"

	got := findingsByRule(t, aps)
	for _, rule := range []string{"WLAN-001", "WLAN-002", "WLAN-003", "WLAN-004", "WLAN-005", "WLAN-006",
		"WLAN-008", "WLAN-010", "WLAN-011", "WLAN-012", "WLAN-020", "WLAN-021", "WLAN-030"} {
		if got[rule] == 0 {
			t.Errorf("rule %s never fired in coverage dataset", rule)
		}
	}
}

func TestDeepRulesFire(t *testing.T) {
	// Hidden SSID (WLAN-009).
	hidden := testAP("02:00:00:00:00:A1", "", 6, "2.4GHz", -70,
		models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, KeyMgmt: "PSK"})
	// WPA3 transition (WLAN-007).
	transition := testAP("02:00:00:00:00:A2", "HybridWiFi", 40, "5GHz", -55,
		models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "WPA2"}, AKMSuites: []string{"SAE", "PSK"}, Transition: true})
	// Evil twin (WLAN-013): same SSID, one open.
	twinSecure := testAP("02:00:00:00:00:A3", "LoungeWiFi", 100, "5GHz", -44,
		models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE"}, PMF: true})
	twinOpen := testAP("02:00:00:00:00:A4", "LoungeWiFi", 6, "2.4GHz", -50,
		models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"})
	// Open AP referenced by a station (WLAN-014).
	openAP := testAP("02:00:00:00:00:A5", "FreeWiFi", 1, "2.4GHz", -48,
		models.SecurityAdvertisement{Enabled: false, Auth: "OPEN"})
	// 2.4 GHz density for WLAN-021.
	var dense []models.AccessPoint
	for i := 0; i < 8; i++ {
		dense = append(dense, testAP(fmt.Sprintf("02:00:00:00:00:B%d", i), fmt.Sprintf("Dense_%d", i), 1+i, "2.4GHz", -60,
			models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA2"}, PMF: true}))
	}

	aps := append([]models.AccessPoint{hidden, transition, twinSecure, twinOpen, openAP}, dense...)
	stations := []models.Station{
		{MAC: "AA:BB:CC:DD:00:01", APBSSID: "02:00:00:00:00:A5", Signal: -48, Associated: true},
		{MAC: "AA:BB:CC:DD:00:02", Signal: -61, ProbedSSIDs: []string{"Net1", "Net2", "Net3", "Net4"}},
	}
	traffic := []models.TrafficObservation{
		{Type: "deauth", Target: "02:00:00:00:00:A4", Count: 4},
		{Type: "deauth", Target: "02:00:00:00:00:A3", Count: 1},
		{Type: "data", Protocol: "http", Target: "02:00:00:00:00:A5"},
		{Type: "data", Protocol: "dns", Target: "02:00:00:00:00:A5"},
		{Type: "data", Protocol: "dot11", Detail: "TKIP-encrypted data frames", Target: "02:00:00:00:00:AA"},
	}

	got := map[string]int{}
	for _, f := range runAllRulesFull(t, aps, stations, traffic) {
		got[f.RuleID]++
	}
	for _, rule := range []string{"WLAN-007", "WLAN-008", "WLAN-009", "WLAN-013", "WLAN-014",
		"WLAN-015", "WLAN-016", "WLAN-017", "WLAN-018", "WLAN-021"} {
		if got[rule] == 0 {
			t.Errorf("rule %s never fired in deep coverage dataset", rule)
		}
	}
	// WLAN-013 must flag the open twin pair but not miscount.
	if got["WLAN-013"] != 1 {
		t.Errorf("WLAN-013: got %d findings, want 1", got["WLAN-013"])
	}
}

var sec6G = models.SecurityAdvertisement{Enabled: true, Protocols: []string{"WPA3", "SAE", "CCMP"}}

func TestFindingsWellFormed(t *testing.T) {
	aps := []models.AccessPoint{
		testAP("02:00:00:00:00:01", "", 6, "2.4GHz", -45,
			models.SecurityAdvertisement{Enabled: false}),
	}
	findings := runAllRules(t, aps)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range findings {
		if f.RuleID == "" {
			t.Error("finding missing RuleID")
		}
		if f.ID == "" {
			t.Error("finding missing ID")
		}
		if !strings.HasPrefix(f.ID, "WLAN-") {
			t.Errorf("finding ID %q missing WLAN- prefix", f.ID)
		}
		if len(f.Evidence) == 0 {
			t.Errorf("rule %s produced finding without evidence", f.RuleID)
		}
	}
}
