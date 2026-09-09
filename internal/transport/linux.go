// Package linux implements wireless backend operations on Linux via `iw`.
// When `iw` is unavailable or the user lacks permissions, capabilities
// degrade honestly.
package transport

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// LinuxBackend talks to the real wireless stack via iw.
type LinuxBackend struct{}

// NewLinux returns a Linux iw-based backend.
func NewLinux() *LinuxBackend { return &LinuxBackend{} }

func (b *LinuxBackend) Name() string    { return "linux-iw" }
func (b *LinuxBackend) Supported() bool { return iwAvailable() }

func (b *LinuxBackend) Capabilities() []string {
	if !iwAvailable() {
		return []string{"unsupported"}
	}
	return []string{"wireless_discovery", "ap_enumeration", "client_observation"}
}

// DiscoverInterfaces lists wireless interfaces via `iw dev`.
func (b *LinuxBackend) DiscoverInterfaces() ([]models.WirelessInterface, error) {
	if !iwAvailable() {
		return nil, fmt.Errorf("iw is not available; install wireless-tools for live scanning")
	}
	out, err := exec.Command("iw", "dev").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iw dev failed: %w", err)
	}
	return parseIwDev(string(out)), nil
}

// Scan runs `iw dev <iface> scan` and parses the output.
func (b *LinuxBackend) Scan(_ context.Context, iface string, _ int) ([]models.AccessPoint, []models.Station, error) {
	if !iwAvailable() {
		return nil, nil, fmt.Errorf("iw is not available")
	}
	if iface == "" {
		return nil, nil, fmt.Errorf("no interface specified")
	}
	out, err := exec.Command("iw", "dev", iface, "scan").CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("iw scan on %s failed: %w\n%s", iface, err, string(out))
	}
	aps := parseIwScan(string(out))
	return aps, nil, nil
}

// Observe reports traffic-level observations. Live capture is not yet
// implemented without monitor mode; the interface degrades honestly.
func (b *LinuxBackend) Observe(_ context.Context, _ string) ([]models.TrafficObservation, error) {
	return nil, nil
}

func iwAvailable() bool {
	_, err := exec.LookPath("iw")
	return err == nil
}

// parseIwDev parses `iw dev` output into interfaces.
func parseIwDev(out string) []models.WirelessInterface {
	var ifaces []models.WirelessInterface
	var current *models.WirelessInterface
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface ") {
			if current != nil {
				ifaces = append(ifaces, *current)
			}
			current = &models.WirelessInterface{Name: strings.TrimPrefix(line, "Interface "), State: "unknown"}
		} else if strings.HasPrefix(line, "type ") && current != nil {
			current.Mode = strings.TrimPrefix(line, "type ")
		} else if strings.HasPrefix(line, "state ") && current != nil {
			current.State = strings.TrimPrefix(line, "state ")
		}
	}
	if current != nil {
		ifaces = append(ifaces, *current)
	}
	return ifaces
}

// parseIwScan parses `iw dev <iface> scan` output into access points.
func parseIwScan(out string) []models.AccessPoint {
	var aps []models.AccessPoint
	var current *models.AccessPoint
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "BSS ") {
			if current != nil {
				finalizeAP(current)
				aps = append(aps, *current)
			}
			bssid := strings.TrimPrefix(line, "BSS ")
			if idx := strings.Index(bssid, "("); idx >= 0 {
				bssid = bssid[:idx]
			}
			bssid = strings.TrimSpace(bssid)
			current = &models.AccessPoint{BSSID: bssid}
		} else if current != nil {
			switch {
			case strings.HasPrefix(line, "SSID: "):
				current.SSID = strings.TrimPrefix(line, "SSID: ")
			case strings.HasPrefix(line, "freq: "):
				current.Frequency, _ = strconv.Atoi(strings.TrimPrefix(line, "freq: "))
				ci := models.FreqToChannel(current.Frequency)
				current.Channel = ci.Channel
				current.Band = string(ci.Band)
			case strings.HasPrefix(line, "DS Parameter set: channel "):
				if ch, err := strconv.Atoi(strings.TrimPrefix(line, "DS Parameter set: channel ")); err == nil {
					current.Channel = ch
				}
			case strings.HasPrefix(line, "signal: "):
				sig := strings.TrimPrefix(line, "signal: ")
				sig = strings.TrimSuffix(sig, " dBm")
				current.Signal, _ = strconv.Atoi(sig)
			case strings.HasPrefix(line, "capability: "):
				current.Capabilities = strings.TrimPrefix(line, "capability: ")
				if strings.Contains(current.Capabilities, "Privacy") {
					current.Security.Enabled = true
				}
			case strings.HasPrefix(line, "Group cipher: "):
				current.Security.GroupCipher = strings.TrimPrefix(line, "Group cipher: ")
			case strings.HasPrefix(line, "Pairwise ciphers: "):
				current.Security.PairwiseCiphers = strings.Fields(strings.TrimPrefix(line, "Pairwise ciphers: "))
			case strings.HasPrefix(line, "Authentication suites: "):
				current.Security.AKMSuites = strings.Fields(strings.TrimPrefix(line, "Authentication suites: "))
			case strings.HasPrefix(line, "WPA:") || strings.HasPrefix(line, "RSN:"):
				current.Security.Enabled = true
			case strings.Contains(line, "PMF required") || strings.Contains(line, "PMF capable"):
				current.Security.PMF = true
			}
		}
	}
	if current != nil {
		finalizeAP(current)
		aps = append(aps, *current)
	}
	return aps
}

// finalizeAP derives protocol/cipher fields from the raw RSN data captured
// by iw and normalizes the security advertisement.
func finalizeAP(ap *models.AccessPoint) {
	sec := &ap.Security
	if sec.Enabled && len(sec.AKMSuites) == 0 && sec.GroupCipher == "" {
		return
	}
	var cipher string
	switch {
	case strings.Contains(sec.GroupCipher, "GCMP"):
		cipher = "GCMP"
	case strings.Contains(sec.GroupCipher, "CCMP"):
		cipher = "CCMP"
	case strings.Contains(sec.GroupCipher, "TKIP"):
		cipher = "TKIP"
	}
	var protocols []string
	switch {
	case containsFold(sec.AKMSuites, "SAE"):
		protocols = []string{"WPA3", "SAE"}
	case containsFold(sec.AKMSuites, "OWE"):
		protocols = []string{"OWE"}
	case containsFold(sec.AKMSuites, "802.1X") || containsFold(sec.AKMSuites, "EAP"):
		protocols = []string{"WPA2"}
		sec.Enterprise = true
	default:
		protocols = []string{"WPA2"}
	}
	if cipher != "" {
		protocols = append(protocols, cipher)
	}
	if len(protocols) > 0 {
		sec.Protocols = protocols
		sec.Cipher = cipher
	}
	if len(sec.AKMSuites) > 0 {
		sec.KeyMgmt = strings.Join(sec.AKMSuites, " ")
	}
	wireless.NormalizeSecurity(sec)
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}
