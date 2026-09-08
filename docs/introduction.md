# Mansa — Introduction

Mansa is QYVORA's terminal-first wireless security assessment framework.
It performs authorized wireless discovery, access-point enumeration,
client observation, WLAN security analysis, and channel/RF analysis, and
produces evidence-backed findings with transparent risk scoring.

## Why Mansa?

- **One workflow, two surfaces.** Every command available in the
  interactive console is also usable one-shot from the shell with the
  same name and flags. Pipe it, script it, or drive it interactively.
- **Deterministic by default.** `--sim` runs a fixed simulation dataset
  designed to exercise every analysis rule. Works offline, offline-first,
  and in CI with no wireless hardware.
- **Evidence over opinion.** Every finding carries the observations that
  produced it, so results are auditable and reproducible.
- **Transparent risk.** Scores are a documented, deterministic function
  of severity and confidence — never a black box.
- **Authorized only.** Mansa enforces an explicit authorization step for
  live assessment scope.

## What it evaluates

- Open networks and hidden SSIDs
- WEP, WPA1-TKIP, WPA2-TKIP, WPA2-CCMP, WPA3, Enterprise (802.1X/EAP)
- WPS exposure
- Channel crowding and overlapping 2.4 GHz channels
- Dense 6 GHz deployments and signal anomalies
- Legacy protocol support advertised in capabilities

## Authorized use

Assess wireless networks you own or are authorized to evaluate.
Unauthorized scanning may be unlawful in many jurisdictions. See
[Authorization](authorization.md) and the LICENSE for the full terms.

Next: [Installation](installation.md).