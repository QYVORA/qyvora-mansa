# Changelog

All notable changes to this project are documented here. This project
follows [Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/) conventions.

## [Unreleased]

### Changed

- **Unified version system** — `internal/version` now carries the canonical
  framework identity (framework, version, commit, date, build user, Go
  version/arch/os) stamped via `-ldflags`, plus official QYVORA contact
  details. `mansa version` renders the full block in terminal and JSON
  formats.
- **Contact details** — the `version` command, README, and `SECURITY.md`
  surface official QYVORA contact: https://qyvora.org ·
  qyvorasec@gmail.com · Tamale, Ghana.
- **WLAN-005 downgraded to `low` and renamed "WPS Advertised"** — an access
  point advertising WPS is observed metadata. It does not establish that
  enrollment is enabled or that the PIN is exploitable, so the previous
  "WPS Enabled"/`medium` pairing claimed more than the evidence supports.
- **WLAN-020 no longer fires on a missing RSSI** — capture sources that do
  not supply a signal report `0`, which is the model's missing-value
  default rather than a real reading. Without the guard every such frame
  raised a spurious finding. Covered by
  `TestSignalAnomalyIgnoresMissingCaptureRSSI`.
- `--dry-run` plan output now routes to stderr when a machine-readable format
  is active, keeping stdout valid.
- Reports are written with mode 0600 in a 0700 directory (matching session
  artifacts) rather than 0644/0750.

### Added

- **Offline capture analysis** (`mansa.capture.analyze`) — PCAP and PCAPNG
  parsing, access-point reconstruction, radiotap and information-element
  decoding, and OUI lookup. Fully offline; no radio and no authorization
  required.
- **Passive live capture** (`mansa.capture.live`) — a TPACKET_V3
  `PACKET_MMAP` block ring over `AF_PACKET` with a syscall fallback, channel
  hopping, and monitor-interface leasing. Authorization required.
- **Bluetooth and BLE as a first-class domain** — five capabilities:
  `bluetooth.advertising.parse`, `bluetooth.gatt.analyze`,
  `bluetooth.hci.parse`, `bluetooth.adapters`, and `bluetooth.scan`.
  Advertisement, ATT and GATT decoders; read-only HCI advertising-report
  parsing; adapter discovery; and passive discovery. Live GATT enumeration
  and pairing are **deliberately absent rather than simulated** — an
  unimplemented capability is not advertised.
- **Hardware capability reporting** (`mansa capabilities --hardware`) —
  separates what is implemented from what this machine can actually observe.
  `--sim` reports simulation availability and requires `--hardware`.

- **Operation framework** — one executor in `internal/operation` runs all three
  operation classes, so validation, active testing, and exploitation share
  identical gating, recording, and evidence rules. Gates apply in order: module
  resolution, required parameters, target presence, authorization, scope,
  hardware capability, and simulation availability. Every gate runs before any
  I/O, and `--dry-run` runs the same gates so a plan cannot describe a run that
  would be refused. Each run writes an `OperationRecord` carrying target, scope,
  operator, interface, simulation flag, frame and byte counts, cleanup state,
  findings, evidence, and stated limitations onto the session.
- **`mansa validate`, `mansa test`, `mansa exploit`** — three commands over one
  module registry, each with a `list` subcommand. Class is a property of the
  module, not the command: an exploitation module is refused through the
  validation command.
- **Validation modules** — `ble.adapter.capabilities` reads controller version,
  BD_ADDR, supported commands, LE features, and LE buffer size using read-only
  HCI commands, without enabling scanning or changing power state;
  `ble.advertising.exposure` reviews collected advertisements for identifiers
  that support tracking; `ble.gatt.access.control` reviews a saved attribute
  table and reports writable characteristics with no reported write protection.
- **Active-test modules** — `wifi.inject.verify`,
  `wifi.management.protection.probe`, and `wifi.authentication.probe` transmit
  a bounded, declared frame set at one authorized target and report what the
  interface answered.
- **Exploitation modules** — `wifi.management.disruption.lab` and
  `wifi.beacon.spoof.lab`, each requiring explicit authorization plus a
  `--param lab` isolated-laboratory acknowledgement. The exploitation registry
  refuses registration without a vulnerability class, affected component, and
  expected-evidence declaration. A disruption run refuses a broadcast station
  address outright.
- **Shared transmit-and-observe harness** (`internal/lab`) — bounded
  transmission, bounded listening, and bounded retention, used by both
  transmitting classes so their safety properties cannot drift. Frames per run
  cap at 256, listen windows at 30s, retained frames at 4096. The executor's
  `HardLimit` caps frames independently of what a module declares. Reported
  counts are what the kernel accepted; nothing claims delivery.
- **Raw frame construction** (`internal/wireless`) — radiotap framing and 802.11
  management frame builders, reachable only through a gated module.
  `BuildDisassociation` refuses a broadcast receiver.
- **Capability contract derived from the module registry** — operation
  capabilities are computed rather than restated, so the published contract
  cannot claim a capability the binary lacks or omit one it provides.
- **Operation lifecycle events** — one started event and exactly one terminal
  event per run, including for a refused run.
- **`docs/active-testing.md` and `docs/exploitation.md`** — gating, bounds,
  cleanup semantics, and what each class may and may not claim.

- **Wireless authorization gate** — the console `authorize` command only
  grants live-assessment consent via `--yes`, the `QYVORA_AUTHORIZED=true`
  environment variable, config `authorized=true`, or an interactive TTY y/N
  prompt; without explicit consent it declines and live wireless assessment
  stays disabled. Passive discovery remains available un-authorized; `--sim`
  mode notes that simulation needs no authorization.
- **Console `environment` command** (`env`) — summarizes the assessed wireless
  environment: channel density, unique SSIDs, stations, and channels that
  require assessment, rendered with bounded rows.
- **Session store hardening** — `session.load` treats its argument as a single
  filename component: relative-only, `.session.json`-suffixed, and always
  resolved inside the session store directory; absolute paths and traversal
  (`..`) are rejected.
- **Report permissions** — assessment and findings reports are written with
  mode 0600 in a 0700 directory, and self-update checks summary and release
  JSON are read through capped readers.
- Full interactive console (REPL) with pipe mode, completion, history,
  contextual prompt, and HUD.
- One-shot CLI mirroring every console command (`assess`, `discover`,
  `scan`, `enumerate`, `observe`, `analyze`, `findings`, `evidence`,
  `report`, `session`, `events`, `target`, `capabilities`, `version`,
  `updates`, `completion`).
- Deterministic offline simulation backend with a dataset exercising all
  analysis rules.
- Authorization gate for live assessment scope (`-y`/`--authorized`).
- 8-stage pipeline: discover → enumerate → observe → analyze →
  validate → findings → risk → report.
- Builtin WLAN analysis rules (WLAN-001 … WLAN-030).
- Transparent, deterministic risk scoring.
- Session store on disk with deduplicating findings and evidence.
- JSONL event stream with a stable, framework-tagged envelope.
- Layered configuration (file/env/flags).
- Self-update with SHA-256 checksum verification.
- Capability contract, machine-readable via `capabilities -o json`.
- Assets (icon/ICO/desktop entry) and installers (`install.sh`,
  `install.ps1`) plus `make install`/`make install-user`.
- Test suite across console parser, rules, pipeline, session, risk,
  config, selfupdate, and CLI.
- GitHub Actions: tests and release workflows; GoReleaser config.

### Fixed

- **`ParseMACAddress` separator offset** — the separator is checked at the
  character before each octet rather than at the octet's own offset, so every
  canonical address form was rejected and only malformed ones could pass.
- **Operation record operator and scope** — a run now records the request's
  operator and the authorization's own scope, rather than the configured
  identity and the module's prerequisites.

## [0.1.0] - 1970-01-01

### Added

- Initial project scaffolding, models, and transport interfaces.

<!--

Release template:

## [X.Y.Z] - YYYY-MM-DD

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

-->
