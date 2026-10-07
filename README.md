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

## Three-Tier Assessment Framework

Mansa provides complete wireless security assessment across three distinct tiers:

### Tier 1: Reconnaissance (Passive/Semi-Passive)

**Purpose**: Discovery and enumeration without state changes on targets

**Modules**:
- `discover` - Wireless interface discovery
- `scan` - Network and access point scanning
- `enumerate` - Detailed AP inventory
- `observe` - Client/station observation
- `capture.analyze` - Offline PCAP analysis
- `bluetooth.scan` - BLE device discovery

**Characteristics**:
- No target state modification
- Minimal detection risk
- No authorization required for offline analysis
- Authorization required for active scanning

**Example**:
```sh
mansa scan --target <network> --authorized
mansa enumerate --target <network> --authorized
```

### Tier 2: Security Techniques (Active Analysis)

**Purpose**: Active security posture assessment and weakness identification

**Modules**:
- `analyze` - Security rule engine
- `validate` - Evidence validation modules
- `test` - Bounded active security tests
- `bluetooth.gatt.enumerate` - Live GATT enumeration
- `credentials.verify` - Credential validation

**Characteristics**:
- Active probing within authorized scope
- Detectable but non-hostile patterns
- Produces findings with evidence
- Authorization required for active modules

**Example**:
```sh
# Active security testing
mansa test wifi.authentication.probe --target <network> --authorized
mansa test wifi.management.protection.probe --target <network> --authorized

# Analysis and validation
mansa analyze
mansa validate ble.gatt.access.control --target <device> --authorized
```

### Tier 3: Exploitation (Proof-of-Concept Validation)

**Purpose**: Controlled validation of identified weaknesses

**Modules**:
- `exploit.wifi.beacon.spoof.lab` - Beacon injection PoC
- `exploit.wifi.management.disruption.lab` - Management frame PoC

**Characteristics**:
- Aggressive, obviously adversarial activity
- Lab environment only (`.lab` suffix)
- Immediate stop after proof
- Explicit authorization + lab parameter required
- High detection risk

**Example**:
```sh
# Lab environment exploitation (authorization required)
mansa exploit wifi.beacon.spoof.lab \
  --target <authorized-lab-target> \
  --interface wlan0 \
  --authorized

# Dry-run to preview impact
mansa exploit wifi.management.disruption.lab \
  --target <target> \
  --dry-run \
  --authorized
```

**Safety boundaries**:
- ≤256 frames per run
- ≤30 second listen window
- Single proof-of-concept only, no sustained attacks
- No post-exploitation or pivoting
- Detailed evidence collection

See [EXPLOITATION.md](EXPLOITATION.md) for complete exploitation guide.

## OPSEC & Operational Profiles

### Noise Levels

Every module declares its operational noise level for OPSEC awareness:

| Level | Description | Detectability | Default Allowed |
|-------|-------------|---------------|-----------------|
| **passive** | Observation only, no emissions | Minimal | ✅ Yes |
| **low** | Blends with normal client behavior | Low | ✅ Yes |
| **moderate** | Active probing, detectable patterns | Medium | ✅ Yes (standard) |
| **aggressive** | Obviously adversarial activity | High | ❌ No (requires explicit) |

**View noise levels**:
```sh
# Capabilities command shows tier and noise for each module
mansa capabilities
```

### Operational Profiles

Three profiles control which modules run based on noise tolerance:

#### Stealth Profile

**Best for**: Covert assessments, minimal footprint

```sh
mansa assess --profile stealth --target <network> --authorized
```

- **Allowed noise**: passive, low only
- **Rate limiting**: 5 seconds between operations
- **Timing jitter**: enabled (anti-fingerprinting)
- **Max parallel**: 1 (single-threaded)
- **Exploitation**: Filtered out (aggressive noise blocked)

#### Standard Profile (Default)

**Best for**: Balanced security assessment

```sh
mansa assess --target <network> --authorized
# or explicitly:
mansa assess --profile standard --target <network> --authorized
```

- **Allowed noise**: passive, low, moderate
- **Rate limiting**: 1 second between operations
- **Timing jitter**: enabled
- **Max parallel**: 4
- **Exploitation**: Not included by default

#### Aggressive Profile

**Best for**: Comprehensive assessment with exploitation

```sh
mansa assess --profile aggressive --target <network> --authorized
```

- **Allowed noise**: all levels (passive through aggressive)
- **Rate limiting**: 100ms between operations
- **Timing jitter**: disabled (speed priority)
- **Max parallel**: 16
- **Exploitation**: Included

### Dry-Run Mode

Preview any operation without execution:

```sh
mansa test wifi.authentication.probe \
  --target <network> \
  --dry-run \
  --authorized
```

**Dry-run shows**:
- Tier classification ([RECON], [TECHNIQUE], [EXPLOIT])
- Noise level and OPSEC footprint
- Authorization requirements
- Target impact assessment
- Reversibility status
- Expected frame count and duration
- Hardware capabilities required

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

**Enhanced output with tier and noise level**:

| ID | Tier | Noise | Risk | Auth |
|---|---|---|---|---|
| `mansa.discover` | - | - | low | no |
| `mansa.scan` | - | - | medium | yes |
| `mansa.enumerate` | - | - | low | yes |
| `mansa.observe` | - | - | low | yes |
| `mansa.analyze` | - | - | low | no |
| `mansa.capture.analyze` | - | - | low | no |
| `mansa.capture.live` | - | - | medium | yes |
| `mansa.bluetooth.adapters` | - | - | low | no |
| `mansa.bluetooth.advertisement.parse` | - | - | low | no |
| `mansa.bluetooth.gatt.analyze` | - | - | low | no |
| `mansa.bluetooth.gatt.enumerate` | - | - | low | yes |
| `mansa.bluetooth.hci.parse` | - | - | low | no |
| `mansa.bluetooth.scan` | - | - | medium | yes |
| `mansa.findings` | - | - | low | no |
| `mansa.evidence` | - | - | low | no |
| `mansa.report` | - | - | low | no |
| `mansa.credentials.verify` | - | - | medium | no |
| `mansa.assess` | - | - | medium | yes |
| `mansa.validate.ble.adapter.capabilities` | validation | passive | low | yes |
| `mansa.validate.ble.advertising.exposure` | validation | passive | low | yes |
| `mansa.validate.ble.gatt.access.control` | validation | passive | low | yes |
| `mansa.test.wifi.inject.verify` | active_test | low | medium | yes |
| `mansa.test.wifi.management.protection.probe` | active_test | low | medium | yes |
| `mansa.test.wifi.authentication.probe` | active_test | moderate | medium | yes |
| `mansa.exploit.wifi.management.disruption.lab` | exploitation | aggressive | high | yes |
| `mansa.exploit.wifi.beacon.spoof.lab` | exploitation | aggressive | high | yes |

**Note**: Modules without a tier/noise are pipeline commands or reporting tools (not operation modules).

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
