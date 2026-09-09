// Package wireless provides WLAN normalization, OUI vendor lookup,
// security parsing, and channel/frequency mapping utilities.
package wireless

import (
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// NormalizeAP fills derived fields (Band, Vendor) on an AccessPoint.
func NormalizeAP(ap *models.AccessPoint) {
	ci := models.FreqToChannel(ap.Frequency)
	if ap.Channel == 0 {
		ap.Channel = ci.Channel
	}
	if ap.Frequency == 0 && ci.Frequency != 0 {
		ap.Frequency = ci.Frequency
	}
	ap.Band = string(ci.Band)
	if ap.Vendor == "" {
		ap.Vendor = VendorFromBSSID(ap.BSSID)
	}
	now := time.Now().UTC()
	if ap.FirstSeen.IsZero() {
		ap.FirstSeen = now
	}
	ap.LastSeen = now
}

// NormalizeSecurity fills the security fields from raw protocol strings.
func NormalizeSecurity(sec *models.SecurityAdvertisement) {
	if len(sec.Protocols) > 0 {
		protos := make([]string, 0, len(sec.Protocols))
		for _, p := range sec.Protocols {
			protos = append(protos, strings.ToUpper(strings.TrimSpace(p)))
		}
		sec.Protocols = protos
		var akms []string
		for _, p := range protos {
			switch {
			case strings.Contains(p, "OWE"):
				sec.Auth = "OWE"
				sec.KeyMgmt = "OWE"
				akms = append(akms, "OWE")
			case strings.Contains(p, "SAE"):
				sec.Auth = "SAE"
				sec.KeyMgmt = "SAE"
				akms = append(akms, "SAE")
			case strings.Contains(p, "PSK"):
				sec.KeyMgmt = "PSK"
				akms = append(akms, "PSK")
			case strings.Contains(p, "EAP"):
				sec.Enterprise = true
				sec.KeyMgmt = "EAP"
				akms = append(akms, "802.1X")
			}
			switch {
			case strings.Contains(p, "CCMP") || strings.Contains(p, "RSN"):
				sec.Cipher = "CCMP"
			case strings.Contains(p, "GCMP"):
				sec.Cipher = "GCMP"
			case strings.Contains(p, "TKIP"):
				sec.Cipher = "TKIP"
			case strings.Contains(p, "WEP"):
				sec.Cipher = "WEP"
			}
		}
		sec.AKMSuites = dedupeStrings(append(sec.AKMSuites, akms...))
	} else if sec.KeyMgmt != "" {
		sec.AKMSuites = dedupeStrings(append(sec.AKMSuites, sec.KeyMgmt))
	}
	if hasAKM(sec.AKMSuites, "SAE") && hasAKM(sec.AKMSuites, "PSK") {
		sec.Transition = true
	}
	if sec.Auth == "" && sec.KeyMgmt == "" {
		if !sec.Enabled {
			sec.Auth = "OPEN"
		} else {
			sec.Auth = "UNKNOWN"
		}
	}
}

func hasAKM(suites []string, want string) bool {
	for _, s := range suites {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, s := range in {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ChannelOccupancy reports how many APs are on each channel.
func ChannelOccupancy(aps []models.AccessPoint) map[int]int {
	counts := make(map[int]int)
	for _, ap := range aps {
		counts[ap.Channel]++
	}
	return counts
}

// BandDistribution counts APs per band.
func BandDistribution(aps []models.AccessPoint) map[string]int {
	counts := make(map[string]int)
	for _, ap := range aps {
		counts[ap.Band]++
	}
	return counts
}
