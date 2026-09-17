# Analysis rules

Mansa applies a fixed, deterministic rule set against the access-point
data in each session. Every rule is implemented as a pure function:
given the same input, it produces the same findings every time.

## Rule catalog

The catalog is the authoritative list of the 21 implemented rules. Rule IDs
are stable capabilities, not a contiguous range: WLAN-019 and WLAN-022–029
are intentionally unassigned (no rule claims those numbers).

| ID        | Name                            | Category        | Severity | What it checks                                      |
|-----------|---------------------------------|-----------------|----------|-----------------------------------------------------|
| WLAN-001  | Open Wireless Network            | open-network    | high     | `security.enabled == false`                        |
| WLAN-002  | WEP Encryption Detected          | weak-crypto     | critical | Protocol list contains WEP                          |
| WLAN-003  | WPA1 with TKIP Cipher            | weak-crypto     | high     | Exact protocol `WPA`/`WPA1` + cipher TKIP          |
| WLAN-004  | WPA2 with TKIP Cipher            | weak-crypto     | medium   | Exact protocol `WPA2` + cipher TKIP                |
| WLAN-005  | WPS Enabled                      | config-weakness | medium   | `security.wps == true`                             |
| WLAN-006  | No Security Protocols Advertised | open-network    | high     | `enabled == false` and protocol list empty          |
| WLAN-007  | WPA3 Transition Mode             | weak-crypto     | medium   | Advertises WPA3/SAE and WPA2/PSK (downgrade path)   |
| WLAN-008  | Protected Management Frames Disabled | config-weakness | medium | WPA2/WPA3 AP without 802.11w PMF advertisement      |
| WLAN-009  | Hidden SSID                      | config-weakness | low      | SSID suppressed (no real confidentiality)           |
| WLAN-010  | Crowded Channel                  | rf-analysis     | low      | ≥3 APs share the same channel                       |
| WLAN-011  | Overlapping 2.4 GHz Channels     | rf-analysis     | low      | Two 2.4 GHz APs within 5 channels of each other     |
| WLAN-012  | High Channel Utilization in 6 GHz| rf-analysis     | info     | ≥5 APs detected in the 6 GHz band                   |
| WLAN-013  | Duplicate SSID / Evil Twin       | rogue-ap        | high     | Multiple BSSIDs share one SSID; open twin ⇒ high    |
| WLAN-014  | Station Associated to Open Network | client-behavior | medium  | Client associated with an open access point         |
| WLAN-015  | Excessive SSID Probing           | client-behavior | info     | Client probes many SSIDs (preferred-network leak)   |
| WLAN-016  | Deauthentication Flood           | rogue-ap        | medium   | Burst of deauthentication frames at a BSSID         |
| WLAN-017  | Cleartext Traffic on Open Network| traffic-exposure| high     | Unencrypted app traffic on an open network          |
| WLAN-018  | Legacy Cipher Traffic            | traffic-exposure| low      | Traffic links using TKIP or WEP ciphers             |
| WLAN-020  | Extremely Strong Signal Nearby   | rf-analysis     | info     | AP with RSSI > −20 dBm                              |
| WLAN-021  | Dense 2.4 GHz Deployment         | rf-analysis     | low      | Many APs share the already-crowded 2.4 GHz band     |
| WLAN-030  | Legacy Protocol Support          | config-weakness | low      | Capabilities string contains `802.11b`/`802.11g`   |

## Detection precision

**WPA vs. WPA2:** Mansa uses exact-protocol matching, not substring
matching. An AP advertising `["WPA2", "TKIP"]` triggers only WLAN-004,
never WLAN-003. An AP advertising `["WPA", "TKIP"]` (pre-WPA2) triggers
only WLAN-003.

## Finding IDs

Every finding carries a deterministic identifier derived from the rule ID
and category:

```
WLAN-<prefix>-<hash>
```

The hash is a truncated SHA-256 of the rule ID, so the same rule always
produces the same ID across sessions.

## Evidence

Each finding carries at least one `Evidence` entry. Evidence records
capture the exact observation that triggered the rule (channel count,
signal strength, protocol list, capabilities string, etc.) so findings
can be independently verified.

## Customization

To extend the rule set, implement a function matching
`func(ctx *rules.Context) []models.Finding` and register it with the
rule engine via `Engine.Add()` or `Engine.AddMany()`. See
`internal/rules/builtin/` for reference implementations.

Next: [Risk scoring](risk-scoring.md).