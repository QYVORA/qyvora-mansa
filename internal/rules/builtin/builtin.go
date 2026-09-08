// Package builtin provides the standard Mansa WLAN security rules.
package builtin

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-mansa/internal/rules"
	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

// All returns the built-in rules in ID order.
func All() []*rules.Rule {
	r := []*rules.Rule{
		openNetworkRule(),
		wepRule(),
		wpa1TkipRule(),
		wpa2TkipRule(),
		wpsRule(),
		noSecurityRule(),
		crowdedChannelRule(),
		overlappingChannelRule(),
		channelUtilizationRule(),
		signalAnomalyRule(),
		legacyProtocolRule(),
	}
	sort.Slice(r, func(i, j int) bool { return r[i].ID < r[j].ID })
	return r
}

func openNetworkRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-001",
		Name:        "Open Wireless Network",
		Category:    "open-network",
		Description: "Access point advertises no encryption; traffic is cleartext.",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfObserved,
		Remediation: "Use WPA3-Personal or WPA2-AES for all networks. Open networks expose all traffic to eavesdropping.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if ap.Security.Enabled {
					continue
				}
				ssid := ap.SSID
				if ssid == "" {
					ssid = "<hidden>"
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-001", "open-network"),
					Title:       fmt.Sprintf("Open network: %s", ssid),
					Category:    "open-network",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s (%s) on channel %d advertises no encryption.", ap.BSSID, ssid, ap.Channel),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: fmt.Sprintf("SSID=%s, security.enabled=false", ssid)},
					},
				})
			}
			return findings
		},
	}
}

func wepRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-002",
		Name:        "WEP Encryption Detected",
		Category:    "weak-crypto",
		Description: "WEP is cryptographically broken and trivially crackable.",
		Severity:    models.SeverityCritical,
		Confidence:  models.ConfObserved,
		Remediation: "Upgrade to WPA3-Personal or WPA2-AES. WEP provides no meaningful security.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if !containsAny(ap.Security.Protocols, "WEP") {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-002", "weak-crypto"),
					Title:       fmt.Sprintf("WEP encryption: %s", ap.SSID),
					Category:    "weak-crypto",
					Severity:    models.SeverityCritical,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s uses WEP which is cryptographically broken.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: fmt.Sprintf("Protocols=%v", ap.Security.Protocols)},
					},
				})
			}
			return findings
		},
	}
}

func wpa1TkipRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-003",
		Name:        "WPA1 with TKIP Cipher",
		Category:    "weak-crypto",
		Description: "WPA1 with TKIP is deprecated and has known vulnerabilities.",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfObserved,
		Remediation: "Upgrade to WPA2-AES (CCMP) or WPA3. TKIP is deprecated in IEEE 802.11-2016.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if ap.Security.Cipher != "TKIP" {
					continue
				}
				if !hasWPA1(ap.Security.Protocols) {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-003", "weak-crypto"),
					Title:       fmt.Sprintf("WPA1-TKIP: %s", ap.SSID),
					Category:    "weak-crypto",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s uses deprecated WPA1 with TKIP cipher.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: fmt.Sprintf("Cipher=%s", ap.Security.Cipher)},
					},
				})
			}
			return findings
		},
	}
}

func wpa2TkipRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-004",
		Name:        "WPA2 with TKIP Cipher",
		Category:    "weak-crypto",
		Description: "WPA2 with TKIP is non-compliant with 802.11n/ac and has known weaknesses.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfObserved,
		Remediation: "Reconfigure for WPA2-AES (CCMP) or WPA3.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if ap.Security.Cipher != "TKIP" {
					continue
				}
				if !hasExactProtocol(ap.Security.Protocols, "WPA2") {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-004", "weak-crypto"),
					Title:       fmt.Sprintf("WPA2-TKIP: %s", ap.SSID),
					Category:    "weak-crypto",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s uses WPA2 with TKIP cipher.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: fmt.Sprintf("Cipher=%s", ap.Security.Cipher)},
					},
				})
			}
			return findings
		},
	}
}

func wpsRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-005",
		Name:        "WPS Enabled",
		Category:    "config-weakness",
		Description: "Wi-Fi Protected Setup is enabled and may be vulnerable to brute-force PIN attacks.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfObserved,
		Remediation: "Disable WPS if not required. Use strong WPA3/WPA2 passphrases.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if !ap.Security.WPS {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-005", "config-weakness"),
					Title:       fmt.Sprintf("WPS enabled: %s", ap.SSID),
					Category:    "config-weakness",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s has WPS enabled.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: "WPS=true"},
					},
				})
			}
			return findings
		},
	}
}

func noSecurityRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-006",
		Name:        "No Security Protocols Advertised",
		Category:    "open-network",
		Description: "Access point advertises no security protocols at all.",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfObserved,
		Remediation: "Deploy WPA3 or WPA2 encryption.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if ap.Security.Enabled {
					continue
				}
				if len(ap.Security.Protocols) > 0 {
					continue
				}
				ssid := ap.SSID
				if ssid == "" {
					ssid = "<hidden>"
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-006", "open-network"),
					Title:       fmt.Sprintf("No security: %s", ssid),
					Category:    "open-network",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s advertises zero security protocols.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: "security.enabled=false, protocols=[]"},
					},
				})
			}
			return findings
		},
	}
}

func crowdedChannelRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-010",
		Name:        "Crowded Channel",
		Category:    "rf-analysis",
		Description: "Multiple APs share the same channel, increasing collision risk.",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfObserved,
		Remediation: "Redistribute APs across less-crowded channels.",
		Detect: func(ctx *rules.Context) []models.Finding {
			counts := make(map[int]int)
			for _, ap := range ctx.APs {
				counts[ap.Channel]++
			}
			var findings []models.Finding
			for ch, count := range counts {
				if count < 3 {
					continue
				}
				bssids := make([]string, 0, count)
				for _, ap := range ctx.APs {
					if ap.Channel == ch {
						bssids = append(bssids, ap.BSSID)
					}
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-010", "rf-analysis"),
					Title:       fmt.Sprintf("Crowded channel %d (%d APs)", ch, count),
					Category:    "rf-analysis",
					Severity:    models.SeverityLow,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("%d APs share channel %d: %s.", count, ch, strings.Join(bssids, ", ")),
					Target:      fmt.Sprintf("channel:%d", ch),
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceChannel, Source: "analysis", Target: fmt.Sprintf("channel:%d", ch),
							Detail: fmt.Sprintf("%d APs on channel %d", count, ch)},
					},
				})
			}
			return findings
		},
	}
}

func overlappingChannelRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-011",
		Name:        "Overlapping 2.4 GHz Channels",
		Category:    "rf-analysis",
		Description: "APs on overlapping 2.4 GHz channels cause co-channel interference.",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfObserved,
		Remediation: "Use non-overlapping channels 1, 6, and 11 in the 2.4 GHz band.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			seen := make(map[string]bool)
			for _, ap := range ctx.APs {
				if ap.Band != string(models.Band24GHz) {
					continue
				}
				for _, other := range ctx.APs {
					if other.BSSID == ap.BSSID || other.Band != string(models.Band24GHz) {
						continue
					}
					key := minKey(ap.BSSID, other.BSSID)
					if seen[key] {
						continue
					}
					if abs(ap.Channel-other.Channel) > 0 && abs(ap.Channel-other.Channel) < 5 {
						seen[key] = true
						findings = append(findings, models.Finding{
							ID:          models.BuildFindingID("WLAN-011", "rf-analysis"),
							Title:       fmt.Sprintf("Overlapping channels: %d & %d", ap.Channel, other.Channel),
							Category:    "rf-analysis",
							Severity:    models.SeverityLow,
							Confidence:  models.ConfObserved,
							Description: fmt.Sprintf("APs %s (ch %d) and %s (ch %d) on overlapping channels.", ap.BSSID, ap.Channel, other.BSSID, other.Channel),
							Target:      ap.BSSID,
							Timestamp:   time.Now().UTC(),
							Evidence: []models.Evidence{
								{ID: models.NewID("ev"), Kind: models.EvidenceChannel, Source: "analysis", Target: ap.BSSID,
									Detail: fmt.Sprintf("ch %d overlaps ch %d", ap.Channel, other.Channel)},
							},
						})
					}
				}
			}
			return findings
		},
	}
}

func channelUtilizationRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-012",
		Name:        "High Channel Utilization in 6 GHz",
		Category:    "rf-analysis",
		Description: "Many APs detected in 6 GHz band.",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfObserved,
		Remediation: "Review 6 GHz channel assignments for non-overlapping distribution.",
		Detect: func(ctx *rules.Context) []models.Finding {
			counts := make(map[string]int)
			for _, ap := range ctx.APs {
				counts[ap.Band]++
			}
			var findings []models.Finding
			for band, count := range counts {
				if band != string(models.Band6GHz) || count < 5 {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-012", "rf-analysis"),
					Title:       fmt.Sprintf("Dense 6 GHz deployment (%d APs)", count),
					Category:    "rf-analysis",
					Severity:    models.SeverityInfo,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("%d APs detected in the 6 GHz band.", count),
					Target:      "band:6GHz",
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceChannel, Source: "analysis", Target: "band:6GHz",
							Detail: fmt.Sprintf("%d APs in 6 GHz band", count)},
					},
				})
			}
			return findings
		},
	}
}

func signalAnomalyRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-020",
		Name:        "Extremely Strong Signal Nearby",
		Category:    "rf-analysis",
		Description: "An access point with very strong signal (above -20 dBm) detected.",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfProbable,
		Remediation: "Investigate whether the signal indicates an unexpected nearby AP.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if ap.Signal > -20 {
					findings = append(findings, models.Finding{
						ID:          models.BuildFindingID("WLAN-020", "rf-analysis"),
						Title:       fmt.Sprintf("Very strong signal: %s", ap.SSID),
						Category:    "rf-analysis",
						Severity:    models.SeverityInfo,
						Confidence:  models.ConfProbable,
						Description: fmt.Sprintf("AP %s has signal strength %d dBm (very strong).", ap.BSSID, ap.Signal),
						Target:      ap.BSSID,
						Timestamp:   time.Now().UTC(),
						Evidence: []models.Evidence{
							{ID: models.NewID("ev"), Kind: models.EvidenceSignal, Source: "scan", Target: ap.BSSID,
								Detail: fmt.Sprintf("Signal=%d dBm", ap.Signal)},
						},
					})
				}
			}
			return findings
		},
	}
}

func legacyProtocolRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-030",
		Name:        "Legacy Protocol Support",
		Category:    "config-weakness",
		Description: "AP advertises support for legacy protocols that may weaken security.",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfObserved,
		Remediation: "Disable legacy protocol support (802.11b, 802.11g mixed mode) if not required.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				caps := strings.ToLower(ap.Capabilities)
				if strings.Contains(caps, "802.11b") || strings.Contains(caps, "802.11g") {
					findings = append(findings, models.Finding{
						ID:          models.BuildFindingID("WLAN-030", "config-weakness"),
						Title:       fmt.Sprintf("Legacy protocol: %s", ap.SSID),
						Category:    "config-weakness",
						Severity:    models.SeverityLow,
						Confidence:  models.ConfObserved,
						Description: fmt.Sprintf("AP %s advertises legacy protocol support in capabilities.", ap.BSSID),
						Target:      ap.BSSID,
						Timestamp:   time.Now().UTC(),
						Evidence: []models.Evidence{
							{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
								Detail: fmt.Sprintf("Capabilities=%s", ap.Capabilities)},
						},
					})
				}
			}
			return findings
		},
	}
}

// helpers

func containsAny(ss []string, targets ...string) bool {
	for _, s := range ss {
		for _, t := range targets {
			if strings.Contains(strings.ToUpper(s), strings.ToUpper(t)) {
				return true
			}
		}
	}
	return false
}

// hasExactProtocol reports whether ss contains target exactly
// (case-insensitive), e.g. "WPA2" does not match "WPA".
func hasExactProtocol(ss []string, target string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, target) {
			return true
		}
	}
	return false
}

// hasWPA1 reports a WPA1-era (pre-WPA2) protocol advertised, without
// matching WPA2/WPA3 entries.
func hasWPA1(ss []string) bool {
	return hasExactProtocol(ss, "WPA") || hasExactProtocol(ss, "WPA1")
}

func minKey(a, b string) string {
	if a < b {
		return a + "|" + b
	}
	return b + "|" + a
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
