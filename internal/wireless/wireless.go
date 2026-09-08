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
		for _, p := range protos {
			switch {
			case strings.Contains(p, "OWE"):
				sec.Auth = "OWE"
				sec.KeyMgmt = "OWE"
			case strings.Contains(p, "SAE"):
				sec.Auth = "SAE"
				sec.KeyMgmt = "SAE"
			case strings.Contains(p, "PSK"):
				sec.KeyMgmt = "PSK"
			case strings.Contains(p, "EAP"):
				sec.Enterprise = true
				sec.KeyMgmt = "EAP"
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
	}
	if sec.Auth == "" && sec.KeyMgmt == "" {
		if !sec.Enabled {
			sec.Auth = "OPEN"
		} else {
			sec.Auth = "UNKNOWN"
		}
	}
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
