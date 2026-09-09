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
		wpa3TransitionRule(),
		pmfDisabledRule(),
		hiddenSSIDRule(),
		crowdedChannelRule(),
		overlappingChannelRule(),
		channelUtilizationRule(),
		evilTwinRule(),
		stationOnOpenNetworkRule(),
		excessiveProbingRule(),
		deauthFloodRule(),
		cleartextTrafficRule(),
		legacyCipherTrafficRule(),
		signalAnomalyRule(),
		denseBandRule(),
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

func wpa3TransitionRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-007",
		Name:        "WPA3 Transition Mode",
		Category:    "weak-crypto",
		Description: "Access point advertises both WPA3/SAE and WPA2/PSK, enabling a downgrade path to the weaker handshake.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfObserved,
		Remediation: "Use WPA3-only (SAE-only) mode. Transition mode leaves passive and offline downgrade attacks possible.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				sec := ap.Security
				if !sec.Enabled {
					continue
				}
				transitionMode := sec.Transition ||
					(akmHas(sec.AKMSuites, "SAE") && akmHas(sec.AKMSuites, "PSK")) ||
					(hasExactProtocol(sec.Protocols, "WPA2") && hasExactProtocol(sec.Protocols, "WPA3"))
				if !transitionMode {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-007", "weak-crypto"),
					Title:       fmt.Sprintf("WPA3 transition mode: %s", ap.SSID),
					Category:    "weak-crypto",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s advertises both strong (SAE/WPA3) and legacy (PSK/WPA2) key management.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: fmt.Sprintf("AKM=%v, transition=true", sec.AKMSuites)},
					},
				})
			}
			return findings
		},
	}
}

func pmfDisabledRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-008",
		Name:        "Protected Management Frames Disabled",
		Category:    "config-weakness",
		Description: "WPA2/WPA3 access point does not advertise 802.11w PMF, leaving management frames spoofable.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfObserved,
		Remediation: "Enable 802.11w/PMF (Required) across the WLAN to protect against deauthentication and spoofing.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				sec := ap.Security
				if !sec.Enabled || sec.PMF {
					continue
				}
				if !hasExactProtocol(sec.Protocols, "WPA2") && !hasExactProtocol(sec.Protocols, "WPA3") {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-008", "config-weakness"),
					Title:       fmt.Sprintf("PMF disabled: %s", ap.SSID),
					Category:    "config-weakness",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s supports WPA2/WPA3 but does not enable 802.11w PMF.", ap.BSSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: "pmf=false"},
					},
				})
			}
			return findings
		},
	}
}

func hiddenSSIDRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-009",
		Name:        "Hidden SSID",
		Category:    "config-weakness",
		Description: "Access point suppresses its SSID; hidden networks provide no real confidentiality and leak the name to active probing.",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfObserved,
		Remediation: "Broadcast the SSID. Hiding it does not prevent discovery and increases client probing behavior.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, ap := range ctx.APs {
				if !ap.Hidden && ap.SSID != "" {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-009", "config-weakness"),
					Title:       fmt.Sprintf("Hidden SSID: %s", ap.BSSID),
					Category:    "config-weakness",
					Severity:    models.SeverityLow,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("AP %s hides its SSID (ssid=%q).", ap.BSSID, ap.SSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ap.BSSID,
							Detail: "hidden=true"},
					},
				})
			}
			return findings
		},
	}
}

func evilTwinRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-013",
		Name:        "Duplicate SSID / Evil Twin",
		Category:    "rogue-ap",
		Description: "Multiple distinct access points broadcast the same SSID; an open or weaker twin enables credential capture.",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfProbable,
		Remediation: "Identify the authorized controller and remove impostor access points. Match BSSIDs against the managed fleet.",
		Detect: func(ctx *rules.Context) []models.Finding {
			groups := make(map[string][]models.AccessPoint)
			for _, ap := range ctx.APs {
				ssid := strings.TrimSpace(ap.SSID)
				if ssid == "" {
					continue
				}
				key := strings.ToLower(ssid)
				groups[key] = append(groups[key], ap)
			}
			var findings []models.Finding
			for _, group := range groups {
				if len(group) < 2 {
					continue
				}
				openTwin := false
				for _, ap := range group {
					if !ap.Security.Enabled {
						openTwin = true
						break
					}
				}
				ssid := group[0].SSID
				bssids := make([]string, 0, len(group))
				for _, ap := range group {
					bssids = append(bssids, ap.BSSID)
				}
				if openTwin {
					findings = append(findings, models.Finding{
						ID:          models.BuildFindingID("WLAN-013", "rogue-ap"),
						Title:       fmt.Sprintf("Possible evil twin: %s", ssid),
						Category:    "rogue-ap",
						Severity:    models.SeverityHigh,
						Confidence:  models.ConfProbable,
						Description: fmt.Sprintf("SSID %q is broadcast by %d APs and at least one is unencrypted: %s.", ssid, len(group), strings.Join(bssids, ", ")),
						Target:      ssid,
						Timestamp:   time.Now().UTC(),
						Evidence: []models.Evidence{
							{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ssid,
								Detail: fmt.Sprintf("SSID=%s, BSSIDs=%s, open_twin=true", ssid, strings.Join(bssids, ","))},
						},
					})
				} else {
					findings = append(findings, models.Finding{
						ID:          models.BuildFindingID("WLAN-013", "rogue-ap"),
						Title:       fmt.Sprintf("Duplicate SSID broadcast: %s", ssid),
						Category:    "rogue-ap",
						Severity:    models.SeverityLow,
						Confidence:  models.ConfPossible,
						Description: fmt.Sprintf("SSID %q is broadcast by %d distinct APs: %s.", ssid, len(group), strings.Join(bssids, ", ")),
						Target:      ssid,
						Timestamp:   time.Now().UTC(),
						Evidence: []models.Evidence{
							{ID: models.NewID("ev"), Kind: models.EvidenceConfig, Source: "scan", Target: ssid,
								Detail: fmt.Sprintf("SSID=%s, BSSIDs=%s, open_twin=false", ssid, strings.Join(bssids, ","))},
						},
					})
				}
			}
			return findings
		},
	}
}

func stationOnOpenNetworkRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-014",
		Name:        "Station Associated to Open Network",
		Category:    "client-behavior",
		Description: "A wireless client is associated with an open access point, exposing its traffic to passive capture.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfObserved,
		Remediation: "Educate clients and enforce WPA2/WPA3 enterprise or VPN on untrusted networks.",
		Detect: func(ctx *rules.Context) []models.Finding {
			openByBSSID := make(map[string]models.AccessPoint)
			for _, ap := range ctx.APs {
				if !ap.Security.Enabled {
					openByBSSID[strings.ToUpper(ap.BSSID)] = ap
				}
			}
			var findings []models.Finding
			for _, st := range ctx.Stations {
				ap, ok := openByBSSID[strings.ToUpper(st.APBSSID)]
				if !ok {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-014", "client-behavior"),
					Title:       fmt.Sprintf("Client on open network: %s", st.MAC),
					Category:    "client-behavior",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("Station %s is associated with open AP %s (SSID %q).", st.MAC, ap.BSSID, ap.SSID),
					Target:      st.MAC,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceObservation, Source: "observe", Target: st.MAC,
							Detail: fmt.Sprintf("AP=%s, security.enabled=false", ap.BSSID)},
					},
				})
			}
			return findings
		},
	}
}

func excessiveProbingRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-015",
		Name:        "Excessive SSID Probing",
		Category:    "client-behavior",
		Description: "A client actively probes multiple SSIDs, advertising its preferred-network history and roaming behavior.",
		Severity:    models.SeverityInfo,
		Confidence:  models.ConfProbable,
		Remediation: "Disable 'auto-join known networks' broadcasts; use enterprise 802.1X or PMF to reduce probe leakage.",
		Detect: func(ctx *rules.Context) []models.Finding {
			var findings []models.Finding
			for _, st := range ctx.Stations {
				if len(st.ProbedSSIDs) < 3 {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-015", "client-behavior"),
					Title:       fmt.Sprintf("Probing station: %s", st.MAC),
					Category:    "client-behavior",
					Severity:    models.SeverityInfo,
					Confidence:  models.ConfProbable,
					Description: fmt.Sprintf("Station %s probes %d SSIDs: %s.", st.MAC, len(st.ProbedSSIDs), strings.Join(st.ProbedSSIDs, ", ")),
					Target:      st.MAC,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceObservation, Source: "observe", Target: st.MAC,
							Detail: fmt.Sprintf("ProbedSSIDs=%s", strings.Join(st.ProbedSSIDs, ","))},
					},
				})
			}
			return findings
		},
	}
}

func deauthFloodRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-016",
		Name:        "Deauthentication Flood",
		Category:    "rogue-ap",
		Description: "A burst of deauthentication frames targeting a BSSID, typical of evil-twin rogues and denial-of-service.",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfObserved,
		Remediation: "Correlate with duplicate/rogue SSID detection and block the offending transmitter.",
		Detect: func(ctx *rules.Context) []models.Finding {
			counts := make(map[string]int)
			for _, t := range ctx.Traffic {
				if !strings.EqualFold(t.Type, "deauth") {
					continue
				}
				counts[t.Target] += max(1, t.Count)
			}
			var findings []models.Finding
			for target, count := range counts {
				if count < 3 {
					continue
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-016", "rogue-ap"),
					Title:       fmt.Sprintf("Deauth flood: %s", target),
					Category:    "rogue-ap",
					Severity:    models.SeverityMedium,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("Observed %d deauthentication frames targeting %s.", count, target),
					Target:      target,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceObservation, Source: "traffic", Target: target,
							Detail: fmt.Sprintf("deauth_count=%d", count)},
					},
				})
			}
			return findings
		},
	}
}

var cleartextProtocols = []string{"http", "telnet", "ftp", "smtp", "pop3", "imap", "dns"}

func cleartextTrafficRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-017",
		Name:        "Cleartext Traffic on Open Network",
		Category:    "traffic-exposure",
		Description: "Unencrypted application traffic observed on an open network is capturable by any listener.",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfObserved,
		Remediation: "Move cleartext protocols behind TLS/SSH/VPN and avoid open WLANs for sensitive services.",
		Detect: func(ctx *rules.Context) []models.Finding {
			openByBSSID := make(map[string]models.AccessPoint)
			for _, ap := range ctx.APs {
				if !ap.Security.Enabled {
					openByBSSID[strings.ToUpper(ap.BSSID)] = ap
				}
			}
			seen := make(map[string]bool)
			var findings []models.Finding
			for _, t := range ctx.Traffic {
				proto := strings.ToLower(t.Protocol)
				if !stringInSlice(cleartextProtocols, proto) {
					continue
				}
				ap, ok := openByBSSID[strings.ToUpper(t.Target)]
				if !ok {
					continue
				}
				key := strings.ToUpper(t.Target) + "|" + proto
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-017", "traffic-exposure"),
					Title:       fmt.Sprintf("%s cleartext on open AP: %s", strings.ToUpper(proto), ap.SSID),
					Category:    "traffic-exposure",
					Severity:    models.SeverityHigh,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("Observed %s traffic on open AP %s (SSID %q).", proto, ap.BSSID, ap.SSID),
					Target:      ap.BSSID,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceObservation, Source: "traffic", Target: ap.BSSID,
							Detail: fmt.Sprintf("protocol=%s, security.enabled=false", proto)},
					},
				})
			}
			return findings
		},
	}
}

func legacyCipherTrafficRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-018",
		Name:        "Legacy Cipher Traffic",
		Category:    "traffic-exposure",
		Description: "Traffic links using TKIP or WEP ciphers are cryptographically weak and crackable.",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfProbable,
		Remediation: "Remove TKIP/WEP from the air; enforce CCMP/GCMP-only WLANs.",
		Detect: func(ctx *rules.Context) []models.Finding {
			seen := make(map[string]bool)
			var findings []models.Finding
			for _, t := range ctx.Traffic {
				detail := strings.ToUpper(t.Detail)
				if !strings.Contains(detail, "TKIP") && !strings.Contains(detail, "WEP") {
					continue
				}
				if seen[strings.ToUpper(t.Target)] {
					continue
				}
				seen[strings.ToUpper(t.Target)] = true
				cipher := "WEP"
				if strings.Contains(detail, "TKIP") {
					cipher = "TKIP"
				}
				findings = append(findings, models.Finding{
					ID:          models.BuildFindingID("WLAN-018", "traffic-exposure"),
					Title:       fmt.Sprintf("Legacy cipher traffic: %s", t.Target),
					Category:    "traffic-exposure",
					Severity:    models.SeverityLow,
					Confidence:  models.ConfProbable,
					Description: fmt.Sprintf("Observed %s-encrypted traffic toward %s.", cipher, t.Target),
					Target:      t.Target,
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceObservation, Source: "traffic", Target: t.Target,
							Detail: fmt.Sprintf("cipher=%s", cipher)},
					},
				})
			}
			return findings
		},
	}
}

func denseBandRule() *rules.Rule {
	return &rules.Rule{
		ID:          "WLAN-021",
		Name:        "Dense 2.4 GHz Deployment",
		Category:    "rf-analysis",
		Description: "Many access points share the already-crowded 2.4 GHz band, guaranteeing co-channel and adjacent-channel interference.",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfObserved,
		Remediation: "Prefer 5 GHz/6 GHz for data clients; assign 2.4 GHz APs to non-overlapping channels 1/6/11.",
		Detect: func(ctx *rules.Context) []models.Finding {
			count := 0
			for _, ap := range ctx.APs {
				if ap.Band == string(models.Band24GHz) {
					count++
				}
			}
			if count < 8 {
				return nil
			}
			return []models.Finding{
				{
					ID:          models.BuildFindingID("WLAN-021", "rf-analysis"),
					Title:       fmt.Sprintf("Dense 2.4 GHz band (%d APs)", count),
					Category:    "rf-analysis",
					Severity:    models.SeverityLow,
					Confidence:  models.ConfObserved,
					Description: fmt.Sprintf("%d access points advertise on the 2.4 GHz band.", count),
					Target:      "band:2.4GHz",
					Timestamp:   time.Now().UTC(),
					Evidence: []models.Evidence{
						{ID: models.NewID("ev"), Kind: models.EvidenceChannel, Source: "analysis", Target: "band:2.4GHz",
							Detail: fmt.Sprintf("2.4GHz_ap_count=%d", count)},
					},
				},
			}
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

func akmHas(suites []string, want string) bool {
	for _, s := range suites {
		if strings.EqualFold(strings.TrimSpace(s), want) {
			return true
		}
	}
	return false
}

func stringInSlice(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
