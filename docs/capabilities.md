# Mansa — Capability Contract

`mansa capabilities` (alias `mansa caps`) prints Mansa's machine-readable
capability contract in terminal and `-o json` formats. `--hardware` adds an
*implemented* vs *available on this host* column, and `--sim` (which requires
`--hardware`) reports simulation availability. A capability that is implemented
but unavailable on the current hardware is reported honestly instead of hidden.

The contract holds **26 capability IDs** — 18 declared capabilities plus 8
operation-derived entries. The operation-derived entries are computed from the
module registry rather than restated, so the published contract cannot
advertise a capability the binary lacks or omit one it provides ([architecture](architecture.md)).

## Declared capabilities

| Capability | Category | Risk | Auth |
|---|---|---|---|
| `mansa.discover` | discovery | low | no |
| `mansa.scan` | enumeration | medium | yes |
| `mansa.enumerate` | enumeration | low | yes |
| `mansa.observe` | observation | low | yes |
| `mansa.analyze` | analysis | low | no |
| `mansa.capture.analyze` | offline-analysis | low | no |
| `mansa.capture.live` | capture | medium | yes |
| `mansa.bluetooth.adapters` | discovery | low | no |
| `mansa.bluetooth.advertisement.parse` | offline-analysis | low | no |
| `mansa.bluetooth.gatt.analyze` | offline-analysis | low | no |
| `mansa.bluetooth.hci.parse` | offline-analysis | low | no |
| `mansa.bluetooth.scan` | discovery | medium | yes |
| `mansa.bluetooth.gatt.enumerate` | discovery | low | yes |
| `mansa.credentials.verify` | analysis | medium | no |
| `mansa.findings` | reporting | low | no |
| `mansa.evidence` | reporting | low | no |
| `mansa.report` | reporting | low | no |
| `mansa.assess` | assessment | medium | yes |

## Operation-derived capabilities

Computed from the operation module registry at runtime.

| Capability | Category | Risk | Auth |
|---|---|---|---|
| `mansa.validate.ble.adapter.capabilities` | validation | low | yes |
| `mansa.validate.ble.advertising.exposure` | validation | low | yes |
| `mansa.validate.ble.gatt.access.control` | validation | low | yes |
| `mansa.test.wifi.inject.verify` | active_test | medium | yes |
| `mansa.test.wifi.management.protection.probe` | active_test | medium | yes |
| `mansa.test.wifi.authentication.probe` | active_test | medium | yes |
| `mansa.exploit.wifi.management.disruption.lab` | exploitation | high | yes |
| `mansa.exploit.wifi.beacon.spoof.lab` | exploitation | high | yes |

## CLI verbs

Mansa's command surface is one set of verbs shared by the console and the
one-shot CLI. The wireless-and-BLE expansion added six verbs on top of the
original assessment commands: `capture`, `bluetooth`, `credentials`,
`validate`, `test`, and `exploit`.

- `capture` — offline PCAP/PCAPNG analysis and passive live capture.
- `bluetooth` — adapter discovery, advertisement/GATT/HCI parsing, and GATT
  enumeration subcommands.
- `credentials` — offline verification of captured handshake material.
- `validate`, `test`, `exploit` — the three operation classes, run through one
  executor with identical gating ([active-testing](active-testing.md),
  [exploitation](exploitation.md)).

Every capability, class, and bound is enforced by the engine before any
input/output or on-air activity; `--dry-run` runs the same gates without
touching a target.

## See also

- [architecture](architecture.md) — how the contract is derived
- [bluetooth](bluetooth.md) — BLE capabilities
- [analysis-rules](analysis-rules.md) — WLAN rule engine
- [stages](stages.md) — the assessment pipeline