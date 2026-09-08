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
				aps = append(aps, *current)
			}
			bssid := strings.TrimPrefix(line, "BSS ")
			if idx := strings.Index(bssid, "("); idx >= 0 {
				bssid = bssid[:idx]
			}
			bssid = strings.TrimSpace(bssid)
			current = &models.AccessPoint{BSSID: bssid}
		} else if current != nil {
			if strings.HasPrefix(line, "SSID: ") {
				current.SSID = strings.TrimPrefix(line, "SSID: ")
			} else if strings.HasPrefix(line, "freq: ") {
				current.Frequency, _ = strconv.Atoi(strings.TrimPrefix(line, "freq: "))
				ci := models.FreqToChannel(current.Frequency)
				current.Channel = ci.Channel
				current.Band = string(ci.Band)
			} else if strings.HasPrefix(line, "signal: ") {
				sig := strings.TrimPrefix(line, "signal: ")
				sig = strings.TrimSuffix(sig, " dBm")
				current.Signal, _ = strconv.Atoi(sig)
			}
		}
	}
	if current != nil {
		aps = append(aps, *current)
	}
	return aps
}
