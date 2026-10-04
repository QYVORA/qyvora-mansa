# Mansa implementation audit

This audit records the current repository state after the architecture,
offline capture, live passive capture, and BLE parsing work. It does not mark
the 37-part master prompt complete.

## Repository and framework consistency

- Mansa remains a Go-native implementation on its existing application,
  pipeline, transport, model, event, session, evidence, and reporting layers.
- `qyvora-tui` remains the published dependency and consumes the existing
  structured event/capability path. No terminal scraping or second TUI was
  introduced.
- `qyvora-common` remains the reference contract; Mansa keeps the existing
  native event envelope and does not import a competing common module.
- `qyvora-dist` is outside this repository's writable root. Its source of
  truth and build-root mismatch are documented in `docs/architecture.md`.
- No external security-tool implementation or source code was copied.

## Implemented in this work

- Architecture and repository-boundary documentation.
- Runtime hardware capability reporting separates implementation from
  observed hardware availability. Simulation remains explicit.
- Bounded 802.11 MAC header and beacon/probe-response information-element
  parsing, including useful security metadata and WPS vendor-element
  presence. WPS presence is observed metadata, not proof that enrollment is
  enabled or exploitable; the built-in rule reports an advertisement for
  review instead of asserting exposure to a PIN attack. Capture-derived APs
  also retain capability flags, supported rates, and basic rates.
- Streaming classic PCAP and PCAPNG readers for raw 802.11/radiotap captures,
  packet bounds, timestamps, context-aware callbacks, and AP/client topology
  extraction.
- `mansa capture analyze` imports capture-derived AP/client observations,
  performs the existing analysis flow, and stores a SHA-256 evidence hash.
- `mansa capture live` passively reads raw frames from an already configured
  Linux monitor interface using `AF_PACKET`, writes classic PCAP, enforces a
  duration limit, checks explicit authorization, refuses to overwrite output,
  and saves a session with evidence and analysis results. It does not change
  interface mode or transmit frames.
- `mansa capture live --sim` emits deterministic beacon and probe-request
  fixtures through the same PCAP writer and session analysis path.
- Live capture parses frames incrementally and emits deduplicated AP/client
  discovery events as packets arrive; the final PCAP pass remains the source of
  the complete saved topology.
- Live packet reception now feeds a bounded, ordered queue with buffer reuse
  and backpressure; consumer failures cancel capture without silently dropping
  queued packets.
- A bounded BLE advertising-data parser and
  `mansa bluetooth parse-advertisement` for offline payload inspection.
- A bounded legacy and extended HCI LE Advertising Report parser exposed as
  `mansa bluetooth parse-hci-event`, producing normalized address, type, RSSI,
  and advertisement data with device-discovered events.
- Normalized GATT snapshot models and `mansa bluetooth analyze-gatt`, which
  reports writable attributes without reported protections as cautious,
  evidence-backed findings without claiming remote reachability.
- A deterministic simulated GATT database with both an unprotected and a
  protected writable characteristic, selectable through `--sim`.
- Read-only Linux Bluetooth HCI adapter metadata discovery from sysfs, exposed
  through `mansa bluetooth adapters` and runtime hardware reporting.
- New behavior is visible through structured events and the machine-readable
  capability registry.

## Validation performed

- `GOCACHE=/tmp/mansa-go-cache go test ./...` passed (rechecked 2026-10-03).
- `GOCACHE=/tmp/mansa-go-cache go test -race ./...` passed (rechecked 2026-10-03).
- `GOCACHE=/tmp/mansa-go-cache go vet ./...` passed (rechecked 2026-10-03).
- `git diff --check` passed (rechecked 2026-10-03).
- Live topology unit tests cover deduplication and radiotap parsing; the CLI
  integration test confirms first-seen discovery events precede final analysis.
  Full `go test ./...`, `go test -race ./...`, and `go vet ./...` passed after
  the live-event implementation.
- WLAN parser/topology, built-in rule, application, and CLI tests passed after
  adding WPS information-element parsing and propagation.
- WLAN parser and topology tests pass after preserving AP capability flags and
  advertised/basic rates in the capture inventory.
- The BLE parser fuzz run completed about 118,000 executions without a crash.
- The HCI advertising-event parser fuzz run completed about 368,000 executions
  without a crash.
- Benchmarks on an Intel Core i7-9850H, linux/amd64 (rechecked 2026-10-03):
  - 802.11 frame parsing: 15.67 ns/op, 0 B/op, 0 allocs/op.
  - PCAP access-point inventory fixture: 26.7 µs/op, 70.7 KB/op,
    12 allocs/op.
  - BLE advertisement fixture: 1.44 µs/op, 376 B/op, 7 allocs/op.
  - HCI legacy advertising report fixture: 1.35 µs/op, 224 B/op,
    6 allocs/op. Extended report parsing is covered by tests but not yet
    benchmarked separately.
- The passive live radio path has not been exercised against physical hardware
  in this environment.
- Bluetooth adapter and GATT paths use synthetic sysfs/JSON fixtures; no
  physical Bluetooth adapter was queried.

## Local SecLists inventory and licensing

The local installation is `/home/wsuits6/seclists`, measures about 5.0 GB, and
identifies itself as MIT-licensed. Its `Passwords/WiFi-WPA` directory is about
64 KB and is the directly relevant password-assessment subset; its broad
`Usernames` directory is about 88 MB and is not specifically a WLAN asset.
SecLists also contains web, fuzzing, payload, and other material that does not
belong in a wireless binary.

No SecLists data was copied or embedded. Its MIT license alone does not settle
dataset provenance, third-party contents, or attribution for each list. The
candidate pipeline is limited to a small MANSA-owned built-in set. Revisit
individual asset provenance before curating any larger embedded subset. The implementation added here is
Go code using the repository's existing dependencies and Linux system calls;
it does not include Aircrack-ng, BlueZ, or other security-tool source.

## Remaining master-prompt work

- Channel enumeration from the radio-reported `iw phy` inventory, channel
  selection, priority ordering, cancellable multi-interface hopping, and channel
  restoration are implemented. Live capture exposes fixed-channel and hopping
  options and advertises them in the capability contract. A temporary Linux monitor-interface lease is wired into live capture and
  removes only the interface it created. Structured events cover creation,
  channel changes, and cleanup. End-to-end adapter validation remains.
- Linux capture now prefers a bounded TPACKET_V3 `PACKET_MMAP` block ring, with
  safe frame-bound checks and a passive syscall receiver fallback when ring setup
  is unavailable. The bounded Go queue preserves ordering and applies
  backpressure. A kernel pre-parse filter and live hardware throughput/drop
  validation remain.
- Live capture streams first-seen AP/client discovery and meaningful updates,
  including hidden-SSID reveals, association changes, and client roaming. AP
  vendor/OUI data is included where the embedded lookup knows it. Broader
  anomaly and rogue-AP analysis remains in the rule engine/audit below.
- Offline capture analysis classifies unprotected WPA/WPA2 EAPOL-Key M1–M4
  messages, correlates observed M1/M2 and M3/M4 replay-counter pairs, records
  PMKID KDE SHA-256 observations, and estimates WEP capture
  conditions from protected legacy-IV headers when the AP advertises WEP. WEP
  IV tracking is bounded at 1,048,576 distinct IVs and marks truncated results;
  it does not claim decryption or key recovery. Cryptographic exchange/MIC
  validation, protocol-specific credential verification, and broader Wi-Fi
  validation remain.
- Linux Bluetooth adapter metadata and passive BLE HCI discovery are implemented;
  scans require an already powered adapter, explicit authorization, and raw HCI
  access, and sessions persist device observations with hashes. A deterministic
  simulation exercises the same path. A read-only HCI controller query reads
  local version, BD_ADDR, supported commands, LE features, and LE buffer size
  without enabling scanning or changing power state. Live classic Bluetooth
  discovery and GATT enumeration remain.
- BLE advertisement simulation and scan-session fixtures exist. Bluetooth
  validation modules are implemented and simulation-covered: controller
  capability reporting, advertising-data exposure review, and GATT write-access
  review. These modules review collected data and emit nothing; live GATT
  enumeration and pairing are deliberately absent rather than simulated.

### Operation framework (Phases 10, 14, 16)

The three operation classes run through one executor, `internal/operation`.
It applies, in order: module resolution, required parameters, target presence,
authorization, scope, hardware capability, and simulation availability. Every
gate runs before any I/O, and `--dry-run` runs the same gates so a plan cannot
describe a run that would be refused. Each run produces an `OperationRecord`
with target, scope, operator, interface, simulation flag, frames and bytes,
cleanup state, findings, evidence, and stated limitations, stored on the
session. Operation events emit one started event and exactly one terminal
event, including for a refused run.

`internal/lab` is the shared transmit-and-observe harness, used by both the
active-test and exploitation classes so their safety properties cannot drift.
It bounds frames per run at 256, listen windows at 30s, and retained frames at
4096, and the executor's `HardLimit` caps frames independently of the module.
It reports what the kernel accepted and never claims delivery. Simulation
counts frames and states that nothing reached the air.

Raw frame assembly lives in `internal/wireless`. `BuildDisassociation` refuses
a broadcast receiver; every builder is reached only through a gated module.

Validation modules (read data, emit nothing): `ble.adapter.capabilities`,
`ble.advertising.exposure`, `ble.gatt.access.control`.

Active-test modules (bounded emission at one authorized target):
`wifi.inject.verify`, `wifi.management.protection.probe`,
`wifi.authentication.probe`.

Exploitation modules (disruptive or impersonating, laboratory-gated):
`wifi.management.disruption.lab`, `wifi.beacon.spoof.lab`. The exploitation
registry refuses registration without a vulnerability class, affected
component, and expected-evidence declaration, and refuses any module not in
the exploitation class. Each exploit additionally requires `--param lab`.

The capability registry derives its operation entries from the module registry
rather than restating them, so the published contract cannot claim a capability
the binary lacks. Documentation for both transmitting classes is in
`docs/active-testing.md` and `docs/exploitation.md`.
- A streaming candidate pipeline now supports a small MANSA-owned built-in set,
  external files/directories, generated values, deterministic prefix/suffix
  mutations, filters, limits, progress, cancellation, and explicit authorization.
  A protocol-specific credential verifier and cryptographic result evidence are
  intentionally unavailable, so no password is reported as recovered. The
  local dataset provenance review and a CLI wordlist workflow remain.
- The session model persists target authorization, operator/audit inputs where
  supplied, and an execution ID correlated with the structured event stream.
  Offline EAPOL/PMKID and WEP capture-condition observations are persisted with
  capture sessions. Operation-specific target scope enforcement and operation
  IDs for future active executors remain; expand cancellation, queue-pressure,
  and hardware-adapter tests alongside those implementations.
- The prompt's documentation set now includes architecture, Bluetooth, hardware,
  authorization, evidence, research/attribution, performance, testing, TUI,
  event, and WLAN guides, plus active-testing and exploitation guides. Protocol
  verification remains unavailable; final end-to-end TUI/JSONL/distribution and
  sibling common-contract reviews remain.
- License review is partial: compiled module licenses were checked, but the
  qyvora-tui module has no license file in the inspected module cache and the
  embedded OUI table provenance remains unresolved.
