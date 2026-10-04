# Mansa

> **Authorized wireless security assessment framework.**
> A terminal-first GUI and CLI for authorized wireless discovery, WLAN
> security analysis, and evidence-driven reporting.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

Mansa is QYVORA's wireless security assessment framework. It runs as a
shared terminal-first console **and** a one-shot CLI with identical
commands, is deterministic and offline-first with `--sim`, enforces an
authorization gate for live scope, and produces evidence-backed findings
with transparent risk scoring.

- **One workflow, two surfaces** — the console commands equal the CLI
  commands.
- **Deterministic `--sim`** — fixed dataset exercises every rule, no
  hardware required, CI-ready.
- **Evidence over opinion** — every finding carries the observations
  that produced it.
- **Authorized only** — a documented authorization gate for live scope.

## Installation

```sh
git clone https://github.com/QYVORA/qyvora-mansa.git
cd qyvora-mansa
make build
sudo make install          # /usr/local layout (root)
make install-user          # ~/.local layout (no root)
```

Or use the release installer:

```sh
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-mansa/main/install.sh | sh
```

See [docs/installation.md](docs/installation.md).

## Quickstart

Full assessment, no hardware, deterministic:

```sh
mansa assess --sim
```

Interactive console (REPL on a real terminal; stdin piping uses a plain line reader):

```sh
mansa
use wlan0
sim on
scan
analyze
findings
report --format markdown
exit
```

Machine-readable output:

```sh
mansa capabilities -o json
mansa capabilities --hardware -o json
mansa analyze -o json
mansa report -f json
```

See [docs/quickstart.md](docs/quickstart.md).

## Commands

```
assess        Run the full wireless assessment pipeline
discover      Discover wireless interfaces and capabilities
scan          Scan for wireless networks and access points
enumerate     Enumerate access-point inventory with filtering
observe       Observe wireless clients/stations and observations
analyze       Analyze the latest session for security findings
findings      Show findings from a session
evidence      Show evidence collected in a session
report        Render a formatting report for a session
session       Inspect saved sessions
events        Show stored events for a session
capture       Analyze offline PCAP/PCAPNG files
validate      Run validation modules that produce evidence
test          Run bounded active tests against an authorized target
exploit       Run authorized exploitation modules in a laboratory
target        Manage assessment targets
capabilities  List the machine-readable capability contract
version       Print version information
updates       Check for and install Mansa updates
completion    Generate shell completion scripts
```

Global flags: `-o/--output`, `-y/--authorized`, `-v/--verbose`,
`-q/--quiet`, `--events`, `--dry-run`.

## Capability contract

24 capabilities, published as a machine-readable contract. The list is
**derived from the module registry**, not restated by hand, so the
published contract cannot advertise a capability the binary does not
provide or omit one it does. Verify against your own build with:

```sh
mansa capabilities
mansa capabilities --hardware   # what this machine can actually do
mansa capabilities --sim        # simulated-data availability
```

| ID | Category | Risk | Auth |
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
| `mansa.findings` | reporting | low | no |
| `mansa.evidence` | reporting | low | no |
| `mansa.report` | reporting | low | no |
| `mansa.assess` | assessment | medium | yes |
| `mansa.validate.ble.adapter.capabilities` | validation | low | yes |
| `mansa.validate.ble.advertising.exposure` | validation | low | yes |
| `mansa.validate.ble.gatt.access.control` | validation | low | yes |
| `mansa.test.wifi.inject.verify` | active_test | medium | yes |
| `mansa.test.wifi.management.protection.probe` | active_test | medium | yes |
| `mansa.test.wifi.authentication.probe` | active_test | medium | yes |
| `mansa.exploit.wifi.management.disruption.lab` | exploitation | high | yes |
| `mansa.exploit.wifi.beacon.spoof.lab` | exploitation | high | yes |

`--hardware` separates *implemented* from *observed available*; a
capability can be implemented and still unavailable on the current host.
`--sim` requires `--hardware`.

### Operation classes

Three classes run through one executor with identical gating — module
resolution, required parameters, target presence, authorization, scope,
hardware capability, then simulation availability. **Every gate runs
before any I/O**, and `--dry-run` executes the same gates without
touching the target.

| Class | Command | Emits findings? | Additional requirement |
|---|---|---|---|
| Offline analysis | `analyze`, `capture analyze`, `bluetooth *` | yes | none |
| Validation | `validate` | no | — |
| Active test | `test` | yes | authorization, scope, bounded frames |
| Exploitation | `exploit` | yes | `--param lab`, vulnerability class + affected component + expected evidence |

Exploitation modules **refuse registration** without a declared
vulnerability class, affected component and expected evidence, and both
Wi-Fi exploitation modules additionally require `--param lab`. See
[exploitation.md](docs/exploitation.md).

Safety bounds: ≤256 frames per run, ≤30 s listen window, ≤4096 retained
frames. The executor applies its own hard frame limit independently of
whatever a module declares.

## Documentation

- [Introduction](docs/introduction.md)
- [Architecture and wireless expansion](docs/architecture.md)
- [Hardware capability reporting](docs/hardware.md)
- [Bluetooth and BLE status](docs/bluetooth.md)
- [WLAN capture and analysis](docs/wireless.md)
- [Active testing](docs/active-testing.md)
- [Exploitation](docs/exploitation.md)
- [Performance](docs/performance.md)
- [Testing and validation](docs/testing.md)
- [Structured events](docs/events.md)
- [Shared TUI integration](docs/tui.md)
- [Installation](docs/installation.md)
- [Quickstart](docs/quickstart.md)
- [Authorization](docs/authorization.md)
- [Modes: sim vs live](docs/modes.md)
- [Pipeline stages](docs/stages.md)
- [Data collection](docs/data-collection.md)
- [Analysis rules](docs/analysis-rules.md)
- [Risk scoring](docs/risk-scoring.md)
- [Sessions & evidence](docs/sessions-and-evidence.md)
- [Output & reporting](docs/output-and-reporting.md)
- [Settings](docs/settings.md)
- [Development](docs/development.md)
- [Troubleshooting](docs/troubleshooting.md)
- [FAQ](docs/faq.md)

## Support

See [SUPPORT.md](SUPPORT.md). Report issues on GitHub.

## About QYVORA

**QYVORA is an African cybersecurity company — built in Tamale, Ghana, serving the
whole continent.** Its mission is to build Africa's strongest cybersecurity
ecosystem and develop the talent to run it.

Mansa is part of a fourteen-framework open-source offensive security toolkit. The
frameworks are unrestricted free software, published for defenders and researchers
across Africa and beyond.

- Company and services: https://qyvora.org
- All frameworks: https://github.com/QYVORA

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Assess wireless networks you own or are
authorized to evaluate.
