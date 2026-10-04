# Mansa architecture and wireless expansion

This document describes the implementation that exists in this repository and
the boundaries for extending it. It is deliberately specific to Mansa; the
shared QYVORA repositories define ecosystem contracts and distribution, not
Mansa's internal implementation.

## Current architecture

```text
CLI / shared TUI
       |
internal/app (application services and configuration)
       |
internal/pipeline (discover, enumerate, observe, analyze, validate, report)
       |
internal/transport.Backend
       |                         \
Linux backend (`iw`)             deterministic simulation backend
       |
pkg/models + internal/events + session/evidence/reporting
```

The CLI and TUI use the same application and command execution paths. The TUI
comes from `github.com/QYVORA/qyvora-tui`; it consumes Mansa's structured event
stream and command/capability metadata. Human-readable terminal output is not a
TUI input contract.

The Linux backend uses `iw` for wireless discovery, channel inventory, channel
selection, and temporary monitor-interface management. A temporary monitor
lease owns only the interface it creates and removes it after capture. Channel
scheduling validates radio-reported frequencies, supports fixed channels and
cancellable priority-ordered hopping across interfaces, and restores prior
channels. Driver/regulatory support remains hardware-dependent.

Linux passive capture prefers a TPACKET_V3 `PACKET_MMAP` receive ring (4 MiB),
with a syscall receiver fallback when ring setup is unavailable. A bounded Go
queue copies borrowed ring bytes, applies backpressure, and sends packets to the
ordered PCAP writer and topology tracker. It does not transmit. The packet
parser handles raw 802.11 management, control, and data frames and strips
radiotap headers. Beacon and probe response information elements decode SSID,
channel, rates, selected RSN cipher/AKM/PMF fields, WPS presence, capability
flags, and supported/basic rates. WPS metadata records an advertised element;
it does not prove enrollment is enabled or exploitable. Live capture emits
first-seen and meaningful AP/client updates, hidden-SSID reveals, association
changes, and roaming events as packets arrive.

The streaming PCAP/PCAPNG readers accept raw 802.11 and radiotap link types and
report malformed frames. `mansa capture analyze <file>` imports AP/client
observations, hashes the source into session evidence, and uses the existing
analysis, risk, session, and report paths. The session model persists the target
authorization context. Offline capture inventory classifies unprotected EAPOL-Key
M1–M4 messages and records PMKID KDE hashes without storing PMKID bytes or
claiming credentials are recoverable. A bounded credential candidate pipeline supports
built-in, external, and generated candidates, but no protocol-specific password
verifier is available, so it cannot report a password as recovered.

Bluetooth adapter metadata, passive Linux BLE HCI discovery, advertisement
parsing, simulation fixtures, and offline GATT metadata review are implemented.
Classic Bluetooth discovery and live GATT enumeration are not. Simulation
exercises the WLAN assessment and capture path without hardware.

## Operation framework

Operation work runs through one shared framework, not three parallel paths.
`internal/operation` holds the module contract, the registry, and the executor;
`internal/lab` holds the transmit-and-observe harness; `internal/active` and
`internal/exploitation` are class-specific module sets; `internal/cli` binds
them to three commands.

| Package                | Responsibility                                              |
|------------------------|-------------------------------------------------------------|
| `internal/operation`   | module metadata, registry, executor, gates, records         |
| `internal/lab`         | bounded transmission, bounded listening, frame observation  |
| `internal/active`      | validation and active-test modules                           |
| `internal/exploitation`| the exploitation registry and its class invariants          |
| `internal/capabilities`| derives the published contract from the module registry     |

The executor applies, in order: module resolution, required parameters, target
presence, authorization, scope, hardware capability, and simulation
availability. Every gate is checked before any I/O. Planning runs the same
gates, so `--dry-run` cannot describe a run that would be refused.

Class assignment is a property of the module, not of the command:

- `validation` modules review data already collected and emit nothing.
- `active_test` modules transmit a bounded, declared frame set at one
  authorized target and report what the interface answered.
- `exploitation` modules drive an authorized target toward a known outcome and
  additionally require an isolated-laboratory acknowledgement.

The executor's `HardLimit` caps frames per run independently of what a module
declares, so a module cannot raise its own ceiling. The capability registry
derives its operation entries from the module registry rather than restating
them, so the published contract cannot claim a capability the binary lacks.

An assembly of raw frames lives in `internal/wireless`. It is not a general
frame library: `BuildDisassociation` refuses a broadcast receiver, and every
builder is reached only through a module that has passed its gates.

The assessment pipeline's `validate` stage remains a stage in the passive
workflow and is unrelated to the `mansa validate` command. Capability output
describes implemented behavior only.

## QYVORA repository boundaries

### `qyvora-common`

`../qyvora-common/contract` is the reference schema and conformance harness.
Frameworks implement the contract natively; Mansa must not add a module import
or duplicate a competing ecosystem contract. Mansa's event envelope already
matches the seven-field JSONL envelope (`schema_version`, `timestamp`,
`execution_id`, `framework`, `level`, `event`, `data`). Keep its schema and
event names compatible, and verify changes against the conformance runner when
machine-facing behavior changes.

### `qyvora-tui`

Use the existing shared TUI package and its structured-event flow. Do not add a
second terminal UI or make it parse progress text. Mansa's capability registry
is already adapted for the shared TUI and CLI output; new capabilities should
come from that registry so the machine output and TUI remain aligned.

### `qyvora-dist`

`../qyvora-dist/tools.def` is the source of truth for installers, release
metadata, and desktop entries. It currently builds Mansa from the repository
root, and the common conformance runner now builds that same root package; the single entry
points currently call the same CLI. Its Mansa desktop description and keywords
also describe generic attack-surface mapping rather than wireless assessment.
These are distribution-repository follow-ups and should be changed there, then
regenerated and checked with that repository's own tests. Do not copy installer
templates or metadata into Mansa.

## Extension rules

- Keep `pkg/models` as the shared domain model layer and preserve existing JSON
  fields and command behavior where practical.
- Put application orchestration in `internal/app`, stage sequencing in
  `internal/pipeline`, transport/hardware details behind `internal/transport`,
  and presentation in the CLI/shared TUI.
- Keep simulation deterministic and usable without wireless hardware. New
  hardware-dependent capabilities should report unavailable honestly.
- Keep passive observation, validation, active testing, and exploitation as
  distinct operations, all running through the shared operation executor.
  Active behavior needs explicit target authorization, scope, cancellation, and
  evidence; it must not be hidden inside scanning.
- Emit structured events using the existing envelope. Human text is for
  people; events are for the TUI and automation.
- Keep machine contracts and capability declarations synchronized with real
  behavior. A registry entry is not a substitute for an implementation.
- Do not shell out to third-party security tools as the implementation of a
  Mansa capability. The existing `iw` dependency is a known transitional
  boundary, not a model for new capture, parsing, or analysis subsystems.
- Do not import sibling repositories as Go modules unless the QYVORA contract
  changes explicitly. The common schema is currently authored for native
  implementation, while TUI is a published Go dependency.

## Remaining extension priorities

See `MANSA_IMPLEMENTATION_AUDIT.md` for the requirement-by-requirement status.
The largest remaining implementation areas are handshake/PMKID analysis,
protocol-specific credential verification, live classic Bluetooth discovery and
GATT enumeration, BPF prefiltering, and end-to-end validation on supported
adapters. The operation-scoped active-testing and exploitation executors are
implemented; see [active testing](active-testing.md) and
[exploitation](exploitation.md). Keep these separate from passive discovery, put
authorization and cleanup in shared execution context, and add deterministic
simulation before depending on physical hardware. Do not describe these as
shipped capabilities until the audit evidence demonstrates them.

## Distribution follow-up

The sibling distribution repository is outside this repository's writable
scope. When working there, reconcile `Q_MAIN_PKG` with the chosen canonical
entry point (`.`) and update the Mansa desktop description and
keywords to identify wireless security assessment. Regenerate outputs from
`tools.def`; do not hand-edit generated installer files.
