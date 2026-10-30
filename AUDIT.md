# AUDIT.md — qyvora-mansa

**Comprehensive capability audit, gap analysis and conformance review.**

- **Repository:** `products/QYVORA-AI/frameworks/qyvora-mansa`
- **Audit date:** 2026-10-21
- **Governing prompt:** `products/QYVORA-AI/PROMPT.md`
- **Audit type:** Static, read-only, evidence-based. No feature implementation.
  **No wireless scan, frame transmission, or hardware interaction was performed.**
- **Method note:** Every claim is **VERIFIED** (source read, binary executed, or
  test run this session) or **INFERRED** (traced from source, not executed).

---

## 1. Framework identity and intended domain

Mansa is QYVORA's **authorized wireless security assessment framework**. Domain:
discovery, enumeration and observation of WLAN/BLE, WLAN security analysis
(including offline PCAP analysis and WPA/WPA2 handshake credential verification),
and — under an explicit authorization + laboratory gate — bounded active tests
and proof-of-concept exploitation.

VERIFIED evidence:

- `README.md:1-5` — "Authorized wireless security assessment framework … for
  authorized wireless discovery, WLAN security analysis, and evidence-driven
  reporting."
- `bin/mansa capabilities -o json` — 26 capability records; `"framework":"mansa"`
  (VERIFIED, executed).
- `internal/capabilities/capabilities.go:1-4` — "the machine-readable capability
  registry … the contract a future QYVORA AI orchestrator can consume."
- `bin/mansa` help — "Authorized use only: assess wireless networks you own or
  are authorized to evaluate."
- Ecosystem doc (`.../QYVORA-SECURITY-FRAMEWORK-ECOSYSTEM.md:92,702,1257`) —
  "Mansa | Wireless (WLAN) | … Eight-stage WLAN assessment pipeline … Expanded
  2026-10-04 … 26 capabilities, WLAN + BLE, offline and live capture, and the
  validate/test/exploit operation framework."

> **Layout caveat.** The repository bears substantial **uncommitted user work**
> (see §12). Under the audit's preservation rule, none of it was touched,
> reverted, or "cleaned up". All findings below are against the working tree as
> found, not against HEAD.

---

## 2. Audit scope and evidence sources

**Scope.** Full read-only audit: CLI surface, capability contract, operation
executor and gates, module registries (passive/validation/active-test/
exploitation), wireless + Bluetooth + WPA stacks, capture pipeline, sessions,
rules, evidence, risk, reporting, layout, tests, and conformance/orchestration.

**Evidence sources (all accessed this session):**

| Source | Path | How used |
|---|---|---|
| Governing prompt | `products/QYVORA-AI/PROMPT.md` | Read fully |
| README | `frameworks/qyvora-mansa/README.md` | Purpose, tiers, contract table |
| Docs | `frameworks/qyvora-mansa/docs/` | Documentation accuracy |
| Capability contract | `internal/capabilities/capabilities.go` | 26 capabilities |
| Capability output | `bin/mansa capabilities -o json` | VERIFIED runtime |
| Operation executor | `internal/operation/executor.go` | Gates, limits |
| Operation model | `internal/operation/operation.go` | Classes, hardware reqs |
| Passive modules | `internal/active/validation.go` | BLE validation modules |
| Active WiFi modules | `internal/active/wifi_active.go` | 3 transmitting tests |
| Exploitation | `internal/exploitation/modules.go`, `registry.go` | 2 lab modules |
| Lab harness | `internal/lab/lab.go` | Frame/listen ceilings |
| Wireless core | `internal/wireless/` | frame/pcap/pcapng/IE parsing |
| Bluetooth | `internal/bluetooth/` | advertising/ATT/GATT/discovery |
| Transport | `internal/transport/` | HCI/AF_PACKET/iw backends |
| WPA | `internal/wpa/wpa.go`, `internal/credentials/` | Handshake verify |
| Events/exit | `internal/events/events.go`, `internal/exitcode/exitcode.go` | Envelope, codes |
| Common layer | `shared/qyvora-common/contract/contract.go`, `.../conformance/runner.go` | Contract + runner |
| Help capture | `docs/audit/help/mansa.txt` | Reference help |
| Tests | `go test ./... -count=1`, `go vet ./...` | VERIFIED |

**Non-destructive binary probes (VERIFIED):**

```
bin/mansa version -o json          → exit 0, identity (commit "none" — dev build)
bin/mansa capabilities -o json     → exit 0, 26 capability records
bin/mansa nosuchcmd                → exit 2  (usage)
bin/mansa --nosuchflag             → exit 2  (usage)
bin/mansa bluetooth scan --adapter hci0 --duration 1s
                                   → exit 3  (authorization refused)   ← no radio I/O
bin/mansa credentials verify --handshake /nonexistent → exit 2
bin/mansa test wifi.authentication.probe --dry-run --sim
                                   → parameter gate refusal; no transmission
bin/mansa assess --sim -o json --events off → exit 0, 8-stage simulated session
```

No command that transmits on an interface or touches hardware was executed. The
`bluetooth scan` probe above failed the authorization gate *before any I/O* and
returned exit 3; it did not scan.

**Git status at audit start (recorded, PRESERVED — not modified):** staged
uncommitted changes listed in full in §12; no untracked files.

---

## 3. Existing capability inventory

The contract publishes **26 capabilities**
(`bin/mansa capabilities -o json`, VERIFIED). Grouped:

**Core pipeline / reporting (8):** `mansa.discover`, `mansa.scan`,
`mansa.enumerate`, `mansa.observe`, `mansa.analyze`, `mansa.findings`,
`mansa.evidence`, `mansa.report`, plus `mansa.assess` (full pipeline).

**Capture (2):** `mansa.capture.analyze` (offline PCAP/PCAPNG),
`mansa.capture.live` (passive live capture from an existing monitor interface).

**Bluetooth/BLE (6):** `mansa.bluetooth.adapters`,
`mansa.bluetooth.advertisement.parse`, `mansa.bluetooth.gatt.analyze`,
`mansa.bluetooth.gatt.enumerate`, `mansa.bluetooth.hci.parse`,
`mansa.bluetooth.scan`.

**Analysis (1):** `mansa.credentials.verify` (WPA/WPA2 handshake verification).

**Operation modules (derived from the registry,
`internal/capabilities/capabilities.go:326-400`) (8):**

- Validation (passive): `mansa.validate.ble.adapter.capabilities`,
  `mansa.validate.ble.advertising.exposure`,
  `mansa.validate.ble.gatt.access.control`.
- Active test: `mansa.test.wifi.inject.verify`,
  `mansa.test.wifi.management.protection.probe`,
  `mansa.test.wifi.authentication.probe`.
- Exploitation (aggressive): `mansa.exploit.wifi.management.disruption.lab`,
  `mansa.exploit.wifi.beacon.spoof.lab`.

The contract is **derived from the module registry**, not hand-maintained
(`capabilities.go:323-325,326-400`), so it cannot advertise a capability the
binary lacks. **VERIFIED**: all 8 module IDs above appear in the live
`capabilities -o json` output and in the registries
(`internal/active/validation.go:27-32`, `internal/exploitation/modules.go:16-19`).

**Analysis rules.** `internal/rules/builtin/builtin.go` defines WLAN-001…WLAN-030
(22 IDs found: 001-021 plus WLAN-030), and the exploitation modules emit
WLAN-EXP-001/002 (`internal/exploitation/modules.go:193,303`); BLE rules BLE-001
(`internal/active/validation.go:248`). **VERIFIED** rule IDs present in source.

---

## 4. Capability status matrix

| Capability | Status | Evidence (file:line) |
|---|---|---|
| Interface discovery (`iw`) | IMPLEMENTED (host-dependent) | `internal/transport/linux.go:118-134,355-377` |
| AP / network scan | IMPLEMENTED (host-dependent) | `internal/transport/linux.go:328-344,378-437` |
| AP enumeration / filtering | IMPLEMENTED | `internal/cli/enumerate` path; `linux.go:378` parser |
| Client/station observation | IMPLEMENTED (live path limited) | `internal/wireless/live_topology.go`; `linux.go:346-348` (`Observe` stub at transport layer) |
| Offline PCAP analysis | IMPLEMENTED | `internal/wireless/pcap.go`, `pcap_access_points.go`, `pcapng.go` |
| Passive live capture | IMPLEMENTED (raw-capture hardware) | `internal/transport/linux.go:49-116`, `linux_ring.go`, `linux_monitor.go` |
| Kernel prefilter | IMPLEMENTED | `internal/transport/prefilter.go`, `linux_prefilter.go` |
| BLE adapter discovery (sysfs) | IMPLEMENTED | `internal/transport/bluetooth_scan_linux.go:30-136` |
| BLE passive scan (HCI) | IMPLEMENTED (BLE adapter) | `bluetooth_scan_linux.go:137-144+` |
| BLE advertisement parse | IMPLEMENTED | `internal/bluetooth/advertising.go` |
| BLE HCI report parse | IMPLEMENTED | `internal/bluetooth/discover.go` |
| Live GATT enumeration (ATT) | IMPLEMENTED (BLE adapter) | `internal/transport/bluetooth_gatt_linux.go:88-160` |
| GATT metadata analysis | IMPLEMENTED | `internal/bluetooth/gatt_analysis.go` |
| WPA handshake parsing | IMPLEMENTED | `internal/wpa/wpa.go`; `internal/wireless/authentication.go` |
| Credential verification (MIC) | IMPLEMENTED | `internal/credentials/wifi.go:170-313` |
| WLAN security rules | IMPLEMENTED | `internal/rules/builtin/builtin.go` (WLAN-001…030) |
| Active test: inject verify | IMPLEMENTED (needs tx hardware) | `internal/active/wifi_active.go:77-120+` |
| Active test: mgmt protection probe | IMPLEMENTED (needs tx hardware) | `internal/active/wifi_active.go` |
| Active test: authentication probe | IMPLEMENTED (needs tx hardware) | `internal/active/wifi_active.go` |
| BLE validation modules (3) | IMPLEMENTED | `internal/active/validation.go:64,164,277` |
| Exploit: management disruption (lab) | IMPLEMENTED (lab + tx hardware) | `internal/exploitation/modules.go:98-193` |
| Exploit: beacon spoof (lab) | IMPLEMENTED (lab + tx hardware) | `internal/exploitation/modules.go:19` (`ModuleBeaconSpoof`), `:302` |
| WEP analysis | PARTIALLY IMPLEMENTED | `mansa.capture.analyze` outputs `wep_capture_conditions`; described as "bounded legacy-IV reuse indicators … not key recovery evidence" (`capabilities.go:149`) |
| PMKID capture | PARTIALLY IMPLEMENTED | `capture.analyze` outputs `pmkid_observations` (`capabilities.go:144`) |
| Deauthentication / disassociation (standalone) | PARTIALLY IMPLEMENTED | frames constructible (`internal/wireless/inject.go:20-27`) and used inside exploits, not exposed as a standalone recon module |
| RF spectrum analysis / SDR | DEFERRED (specialised) | No SDR code; see §9 |
| Monitor-mode chipset management | IMPLEMENTED (hardware-gated) | `internal/transport/linux_monitor.go`; capability `wifi.monitor_mode` |
| Bluetooth pairing / connection attacks | NOT APPLICABLE / DEFERRED | Modules explicitly avoid pairing/connecting (`bluetooth_gatt_linux.go` doc) |

---

## 5. Reconnaissance and discovery findings

**Wireless interface discovery (IMPLEMENTED).** `LinuxBackend.DiscoverInterfaces`
shells to `iw dev` and parses (`linux.go:118-134,355-377`); degrades honestly when
`iw` is absent (`linux.go:123-125`). `Capabilities()` reports
`wireless_discovery`/`ap_enumeration` only when `iw` is present
(`linux.go:29-36`).

**Access-point / network scan (IMPLEMENTED).** `Scan` runs
`iw dev <iface> scan` and parses output into `models.AccessPoint`
(`linux.go:328-344,378-437`), normalizing the security advertisement
(`finalizeAP`, `linux.go:439+`).

**Client/station observation (PARTIALLY IMPLEMENTED).** `live_topology.go` models
stations; the transport-level `Observe` returns without a live implementation on
Linux (`linux.go:346-348`) — live client observation depends on raw capture and
the topology builder. **INFERRED**: richness comes from capture analysis rather
than a dedicated observe backend.

**Offline capture discovery (IMPLEMENTED — high-level).** The strongest passive
capability:
- Classic PCAP and PCAPNG parsing with link-type detection
  (`internal/wireless/pcap.go:14-20`, `pcapng.go`), supporting
  `linkTypeIEEE80211` (105) and `linkTypeRadiotap` (127) (`pcap.go:15-16`).
- 802.11 information-element parsing including RSN, HE operation, 6 GHz detection
  (`internal/wireless/information_elements.go:41-273`).
- AP inventory reconstruction with bounded topology limits
  (`pcap_access_points.go:33-52`, limits at `pcap.go:16-18`).

**BLE discovery (IMPLEMENTED).** Adapter discovery is sysfs-only and does **not**
power on, scan, or connect (`transport/bluetooth_scan_linux.go:27-30`); passive
scan reads HCI LE advertising reports from an already-powered adapter and never
pairs or connects (`bluetooth_scan_linux.go:137-144`). Offline HCI
advertisement-report parsing is available (`bluetooth/discover.go`).

**Environment-aware prerequisite detection (IMPLEMENTED — a strength).** The
hardware report separates *implemented* from *observed-available*
(`pkg/models/hardware_capability.go:16-28,57-78`) and is exposed via
`capabilities --hardware` (`README.md:294,331-333`). Capability identifiers
include `wifi.interface_discovery`, `wifi.ap_enumeration`,
`wifi.client_observation`, `wifi.raw_capture`, `wifi.kernel_prefilter`,
`wifi.frame_injection`, `wifi.monitor_mode`, `bluetooth.adapter_discovery`,
`bluetooth.discovery`, `ble.discovery`, `ble.gatt` (`hardware_capability.go:66-78`).

---

## 6. Analysis and assessment findings

**WLAN security rule engine (IMPLEMENTED).** WLAN-001…WLAN-030
(`internal/rules/builtin/builtin.go`) analyse APs/stations/observations. Rules are
tested (`builtin_test.go`), including assertions that no finding is emitted
without evidence (`builtin_test.go:203`).

**WPA/WPA2 analysis (IMPLEMENTED).** `internal/wpa/wpa.go` implements:
- KDF selection and PBKDF2 with the mandated 4096 iterations (`wpa.go:59-60`).
- MIC sizes for SHA-1 (8) and SHA-256 (16) suites (`wpa.go:52-79`).
- EAPOL-Key body layout derivation independent of a claimed MIC length
  (`wpa.go:112-155`), replay-counter extraction (`wpa.go:157`).
- `VerifyMIC` over header+body.

**Credential verification (IMPLEMENTED).** `internal/credentials/engine.go` runs a
wordlist through a `Verifier` (`engine.go:87-144`); `wifi.go` builds a
`WPAVerifier` from captured handshakes (`wifi.go:170-220`), derives the PMK
(`wifi.go:229`), and checks the MIC (`wifi.go:267-292`). It is scoped by target
(`wifi.go:241`) — VERIFIED it refuses without authorization (probe → exit 2/3 on
the CLI path). Tests exist (`credentials/engine_test.go`, `wifi_test.go`,
`wpa_test.go`).

**BLE/GATT assessment (IMPLEMENTED).** `gatt_analysis.go` reviews saved GATT
metadata for writable characteristics lacking reported
encryption/authentication/authorization (`capabilities.go:177-184`); the
advertising-exposure validation module emits BLE-001 for tracking-supporting
identifiers (`active/validation.go:247-249`).

**Risk scoring, evidence, sessions (IMPLEMENTED).** `internal/risk/risk.go`,
`internal/evidence/evidence.go`, `internal/session/session.go` (with test).

**False-positive / honesty controls (a strength).** Exploitation limitations state
that "radio conditions produce the same observable silence as working protection"
and that a run observing nothing reports no negative result
(`exploitation/modules.go:71-82`); `CaptureSummary` counts `Malformed` packets
(`pcap.go:40-46`).

---

## 7. Exploitation-related capability findings

Mansa has a **deliberately bounded, gated exploitation surface** — the most
significant differentiator from kush.

**Two laboratory exploits (IMPLEMENTED, gated):**

- `mansa.exploit.wifi.management.disruption.lab` — sends a bounded burst of
  disassociation frames to **one** authorized station
  (`internal/exploitation/modules.go:19,98-193`); CWE-306, component and expected
  evidence declared (`modules.go:100-104`).
- `mansa.exploit.wifi.beacon.spoof.lab` — beacon impersonation
  (`modules.go:19,302`).

**Registration hard requirements (VERIFIED):** every exploit must declare a
vulnerability class, affected component and expected evidence, plus the `lab`
parameter, or it **refuses registration**
(`exploitation/modules.go:26-68`; registry in `exploitation/registry.go`;
README:350-353).

**Safety bounds (VERIFIED):** `internal/lab/lab.go` enforces
`MaxFramesPerRun = 256` (`lab.go:30-31`), a listen-window ceiling
(`lab.go:33,167-170`), and frame-ceiling refusal before transmission
(`lab.go:156-164`). The executor applies its own hard frame limit independently
of module declarations (`README.md:355-357`; `executor.go:13` `DefaultHardLimit`).
`Result.OverAirConfirmed()` always returns false — the harness never claims a
frame reached the air (`lab.go:136`).

**Authorization / confirmation / scope gates (IMPLEMENTED).** The executor runs,
in order: module resolution → parameters → target presence → authorization →
scope → simulation-availability → hardware, with confirmation last
(`executor.go:250-322`). Refusals are typed (`executor.go:53-76`) and carry the
gate name. VERIFIED: `bluetooth scan` without `--authorized` → exit 3; a
parameter-gate refusal for `test wifi.authentication.probe` was observed without
any transmission.

**Post-exploitation / persistence / pivoting:** **NOT APPLICABLE / out of
scope** — README:190-194 states "No post-exploitation or pivoting". This is an
intentional domain boundary, not a gap.

**Cleanup:** `CleanupState` is recorded on outcomes (`executor.go:387`);
monitor-interface creation/removal emits lifecycle events
(`events.go:MonitorInterfaceCreated/Removed`).

---

## 8. High-level implementation candidates (P0–P3)

Feasible with the current machine/dependencies (offline data, no specialised
radio). Recommendations only.

- **P1 — Standalone offline 802.11 frame-analysis commands.** The parsers exist
  (`information_elements.go`, `pcap_access_points.go`) but are reachable mainly
  through `capture analyze`. Exposing targeted offline decoders (e.g. EAPOL
  summary, RSN suite listing, IE anomaly view) is pure file processing.
- **P1 — WEP/poor-crypto offline assessment expansion.** `wep_capture_conditions`
  is baseline; deeper offline IV/weak-crypto analysis is feasible on captured data
  (explicitly "not key recovery evidence" today, `capabilities.go:149`).
- **P1 — BLE advertisement/GATT offline rule depth.** Add offline rules over
  recorded advertisements/GATT metadata (tracking, sensitive data exposure) —
  `gatt_analysis.go` and `advertising.go` already provide the inputs.
- **P2 — PCAPNG extended-block coverage and capture summarisation.** Deepen
  `pcapng.go` parsing for multi-interface captures and richer summaries.
- **P2 — Deterministic `--sim` breadth.** Extend the simulation dataset so more
  rules/modules are exercised in CI without hardware (the fixture already
  supports `--sim`, `transport/simulate.go`).
- **P3 — Stakeholder report templates / finding correlation.** Reporting exists;
  correlation and prioritisation across sessions would improve usability.

---

## 9. Low-level deferred technique inventory (DEFERRED — SPECIALISED PREREQUISITES)

Mansa already *implements* substantial gated live capability (monitor-mode,
raw frame injection, monitor-interface management) but each requires **specific
hardware and privileges**. The techniques below remain deferred.

| Technique | Objective | Prerequisites | Feasibility | Status | Deferral reason | Conditions to implement |
|---|---|---|---|---|---|---|
| Monitor-mode / raw-injection hardware operation | Passive capture + active tests/exploits | Monitor-mode-capable adapter, `CAP_NET_RAW`, `iw` | High (with hardware) | IMPLEMENTED but hardware-gated | Current host may lack a capable radio; code already refuses honestly | A supported monitor/injection adapter + root |
| RF spectrum analysis / SDR | Non-802.11 RF survey, jamming detection | SDR hardware (e.g. HackRF/USRP), DSP stack | Medium | MISSING / DEFERRED | No SDR dependency; out of current scope | Add SDR backend module + hardware |
| Bluetooth classic (BR/EDR) attacks | Legacy pairing/KNOB etc. | Class-capable BT adapter, spoofing | Low-Medium | MISSING / DEFERRED | Domain currently BLE-only; pairing explicitly avoided | Dedicated BT-class stack + hardware |
| BLE active exploitation (write/impersonation) | Prove BLE access-control weaknesses | BLE adapter, ATT write | Medium | DEFERRED (read-only only today) | Modules deliberately never write/pair (`bluetooth_gatt_linux.go` doc) | Add gated, lab-scoped BLE write module |
| Wi-Fi handshake capture (live) + cracking | Obtain handshake from air | Monitor/injection adapter | High (with hardware) | PARTIALLY (offline verify implemented; live capture requires hardware) | Requires monitor hardware; cracking is offline | Capture live handshake then verify offline |
| Evil-twin / rogue AP with captive portal | Assess client credential exposure | Two radios (AP + monitor) | Medium | MISSING / DEFERRED | Multi-radio lab required; high risk | Isolated lab with dual radios |
| Channel-based / hardware-specific driver exploits | Firmware-level assessment | Vendor-specific adapters, lab | Low | MISSING / DEFERRED | Hardware/firmware research environment | Dedicated lab |
| GPS/cellular correlation | Geo/asset mapping | GPS/cellular receivers | Low | MISSING / DEFERRED | Not in domain | Optional external data source |

All are **DEFERRED — SPECIALISED PREREQUISITES**. None is classified irrelevant.

---

## 10. Common-layer conformance

Reference: `shared/qyvora-common/contract/contract.go`; conformance runner
`shared/qyvora-common/conformance/runner.go` (VERIFIED `known("mansa")` descriptor
at `runner.go:152-153`).

| Dimension | Classification | Evidence / rationale |
|---|---|---|
| Exit codes 0/1/2/130 | SHARED (conformant) | `internal/exitcode/exitcode.go`; VERIFIED unknown cmd/flag → 2 |
| Exit code 3 (refused/unsupported) | SHARED (conformant) | `internal/exitcode` `AuthorizationRefused=3`; VERIFIED `bluetooth scan` without auth → 3; `credentials_test.go:214` asserts it |
| Framework identity block | SHARED (conformant) | `internal/version/version.go:GetInfo`; VERIFIED `version -o json` |
| Semver identity | CONFORMANT (build caveat) | Binary reports `v0.1.0` but `commit:"none"`,`date:"unknown"` — a dev/untagged build. Release stamping expected via ldflags (`version.go` doc) |
| JSONL event envelope | SHARED (conformant) | `internal/events/events.go:1-9` — matches `contract.Envelope`; shared verbs use ecosystem spelling exactly (`events.go:18-21`) |
| Capability manifest | FRAMEWORK-SPECIFIC (superset) | `capabilities.go:20-44` `Tool` is far richer than `contract.CapabilityManifest` (adds tier/noise/risk/auth/hardware/schema) — appropriate for a domain with safety gates |
| Per-operation input/output schema | SHARED (conformant, ahead of contract) | `capabilities.go:46-65` `Param`/`OutputField`/`Schema` — more expressive than the reference contract; a model the common layer could adopt |
| `--events` flag | SHARED (conformant) | `root.go`; runner descriptor `EventsFlag:"--events"` |
| Output format flag `-o` | SHARED (conformant) | runner descriptor `FormatFlag:"-o"`; `-o json` VERIFIED |
| Structured result document | SHARED (conformant) | `assess --sim -o json` returns canonical session document (VERIFIED) |
| Config load/validation | DUPLICATED | `internal/config/config.go` (viper) structurally mirrors kush's |
| Typed exit errors | DUPLICATED | `internal/errors/errors.go` `ExitError` ≈ kush's `internal/errors` |
| Risk/noise/authorization metadata | SHARED concept, rich model | `pkg/models/operation.go`, `noise`/`risk` fields — the common layer defines `Command.Dangerous/Authorization`; mansa's model is a superset |
| Hardware capability reporting | FRAMEWORK-SPECIFIC | `pkg/models/hardware_capability.go` — genuinely domain-specific, should remain so |
| TUI retirement `//go:build ignore` | SHARED convention | `internal/cli/tui.go:1` — same fleet-wide pattern as kush |
| `--authorized`/`--dry-run`/`--param` gating flags | FRAMEWORK-SPECIFIC | Domain safety primitives (`root.go`); not forced onto offline tools |

**Key finding.** Mansa is the **most conformance-complete of the two**
frameworks: it implements exit code 3, the event envelope, identity, `-o`, and
`--events`, and its capability schema is *ahead* of the reference contract. The
duplicated `internal/errors` and `internal/config` are the main consolidation
candidates.

---

## 11. AI orchestration readiness

Statuses per PROMPT.md §9.

| Requirement | Status | Evidence |
|---|---|---|
| Stable discoverable identity | CONFORMANT | `version -o json` → `"framework":"mansa"` (VERIFIED) |
| Version/compatibility metadata | PARTIALLY CONFORMANT | `version.go:GetInfo` complete, but the shipped binary is an unstamped dev build (`commit:"none"`) |
| Machine-readable capability description | CONFORMANT | `capabilities -o json`, 26 records (VERIFIED) |
| Explicit operation inputs/outputs | CONFORMANT | `Schema{Input,Output}` per operation tool (`capabilities.go:61-65,389-395`) |
| Predictable exit codes/errors | CONFORMANT | 0/1/2/3/130; VERIFIED |
| Structured results/evidence | CONFORMANT | `assess -o json` canonical doc; `internal/evidence` |
| Clear prerequisite declarations | CONFORMANT | Prerequisites/limitations/cleanup folded into capability descriptions (`capabilities.go:350-363`) |
| Permission/authorization requirements | CONFORMANT | `authorization_required`/`confirmation_required` per tool; runtime gate `executor.go:292-321` |
| Timeouts and cancellation | CONFORMANT | `signal.NotifyContext` (`root.go:55`); op `MaxDuration`; capture ≤1 h |
| Resource/concurrency constraints | CONFORMANT | Frame ceilings (`lab.go:30`), listen ceilings (`lab.go:33`), capture limits (`pcap.go:17-18`) |
| Safe execution defaults | CONFORMANT | Dry-run plans, authorization gate, confirmation gate; passive/validation require no over-air action |
| Read-only vs state-changing distinction | CONFORMANT | `changes_state`/`reversible` per tool (`capabilities.go:33-34`) |
| Risk classification / confirmation | CONFORMANT | `risk`, `noise_level`, `tier` per tool; aggressive noise requires explicit profile (`README.md:200-263`) |
| Consistent logging/correlation | CONFORMANT | `execution_id` in events and results |
| Compatibility with common contract | CONFORMANT | See §10; runner descriptor present (`runner.go:152`) |
| Honest unsupported reporting | CONFORMANT | `--hardware` separates implemented vs available; refusals name the gate |

**Orchestration verdict: CONFORMANT.** Mansa is explicitly built to be
orchestrated: the contract header says so (`capabilities.go:1-4`), operation
tools carry full schemas, risk/noise/authorization metadata, and hardware
requirements, and every gate runs before I/O. The one weakness is the unstamped
dev build identity (`commit:"none"`), which affects provenance but not
discoverability.

**Proposed future contract (not implemented):** promote mansa's `Schema{Param,
OutputField}` shape into the common contract so all 14 frameworks expose
per-operation input/output schemas identically; standardise the `tier`/
`noise_level` vocabulary.

---

## 12. CLI, repository-layout, and documentation findings

### Pre-existing uncommitted user work — PRESERVED (recorded verbatim)

`git status` at audit start (staged, not committed). **None of the following was
touched, reverted, or cleaned up:**

```
Changes to be committed:
  modified:   EXPLOITATION.md
  renamed:    mansa-main-logo.png -> assets/mansa-main-logo.png
  renamed:    docs/EXPLOITATION.md -> docs/EXPLOITATION-REFERENCE.md
  renamed:    BEFORE-AFTER-COMPARISON.md -> docs/IMPLEMENTATION-HISTORY/BEFORE-AFTER-COMPARISON.md
  renamed:    IMPLEMENTATION-STATUS.md -> docs/IMPLEMENTATION-HISTORY/IMPLEMENTATION-STATUS.md
  renamed:    MANSA_IMPLEMENTATION_AUDIT.md -> docs/IMPLEMENTATION-HISTORY/MANSA_IMPLEMENTATION_AUDIT.md
  renamed:    PHASE-1-CHECKLIST.md -> docs/IMPLEMENTATION-HISTORY/PHASE-1-CHECKLIST.md
  renamed:    PHASE-1-COMPLETION-REPORT.md -> docs/IMPLEMENTATION-HISTORY/PHASE-1-COMPLETION-REPORT.md
  renamed:    PHASE-1-SUMMARY.md -> docs/IMPLEMENTATION-HISTORY/PHASE-1-SUMMARY.md
  modified:   docs/development.md
  modified:   docs/exploitation.md
  modified:   docs/faq.md
  modified:   install.ps1
  modified:   install.sh
```

`git diff --cached --stat` (VERIFIED): 14 files changed, 10 insertions(+),
9 deletions(-); the logo move is the only binary (`Bin`). No untracked files.
This is meaningful in-progress documentation/layout work by the user.

### Layout (exact paths; nothing moved/deleted)

- **Binary placement — CORRECT:** `bin/mansa` (12.4 MB). `bin/` gitignored
  (`.gitignore`). No compiled binary in the repo root.
- **Root strays (recorded, NOT moved):**
  - `continue_A1.sh` (43 B, tracked) — a one-line `opencode -s
    ses_…` session-restart helper. Development shell-out artifact at repo root.
  - `EXPLOITATION.md` (11.5 KB, tracked, currently modified) — root-level
    exploitation guide; a `docs/EXPLOITATION.md` also exists (being renamed to
    `docs/EXPLOITATION-REFERENCE.md` in the uncommitted work). **Duplicate-purpose
    documentation between root and docs/** — P2.
  - `PROMPT.md` (31.9 KB, tracked) — a framework-specific prompt at repo root.
  - `sessions/` (untracked, gitignored, `0600` mode dir with 4
    `sess-*.session.json` files) — runtime session artifacts.
  - `reports/` (gitignored) — runtime reports.
- **Assets — CORRECT (after in-progress move):** previously `mansa-main-logo.png`
  sat at repo root; the uncommitted work moves it to `assets/mansa-main-logo.png`
  alongside `assets/mansa.desktop`, `assets/mansa.ico`, `assets/mansa.png`.
  The move is the user's; it corrects a placement issue flagged by the ecosystem
  conventions.
- **Docs** — `docs/` is substantial (30+ real `.md` files, including the
  in-progress `IMPLEMENTATION-HISTORY/` subdirectory). Unlike kush, mansa has no
  zero-byte placeholder docs. **Documentation is a strength**, though the
  root-vs-docs `EXPLOITATION.md` duplication and the mid-rename state (root
  `README.md:196,353` still reference `EXPLOITATION.md`/`docs/exploitation.md`)
  are P2 accuracy items.
- **CI — note a potential duplication:** `.github/workflows/` contains `ci.yml`,
  `release.yml`, **and** `tests.yml`. Three workflow files where kush has two.
  P3: confirm `tests.yml` is not redundant with `ci.yml`.
- **Root docs metadata:** `CHANGELOG.md` (9.3 KB), `SECURITY.md` (1.8 KB),
  `GOVERNANCE.md`, `CONTRIBUTING.md`, `SUPPORT.md`, `NOTICE`, `LICENSE` are all
  **non-empty** (VERIFIED) — unlike kush.

### CLI

- Canonical tier grammar (`recon`/`exploit`/`report`) with hidden legacy aliases
  (`internal/cli/root.go:241-257`) — VERIFIED `mansa scan --help` works.
- Rich global flags: `-o`, `-y/--authorized`, `--dry-run`, `--events`,
  `--verbose`, `--quiet`, `--update`, `--allow-shellout` (`root.go`).
- Gate-first execution: every gate runs before I/O (`executor.go:134,250-322`).

---

## 13. Testing and verification findings

**Only checks actually run are reported.**

- `go test ./... -count=1 -timeout 180s` → **PASS** (exit 0). Notably
  `internal/transport` took ~20 s (received real timer behaviour in tests);
  `internal/cli` 0.43 s; `internal/credentials` 0.33 s. Tested packages include
  `active`, `app`, `bluetooth`, `capabilities`, `cli`, `config`, `credentials`,
  `exploitation`, `lab`, `operation`, `pipeline`, `rules/builtin`, `selfupdate`,
  `session`, `transport`, `wireless`, `wpa`, `pkg/models`. Packages without
  tests: `events`, `evidence`, `exitcode`, `findings`, `logger`, `output`,
  `reporting`, `risk`, `rules`, `table`, `target`, `ui`, `validation`, `version`.
  VERIFIED from the run output.
- `go vet ./...` → **PASS** (exit 0, no findings).
- Capability probes as listed in §2 (all VERIFIED, none transmitted).

**Not run (recorded as UNVERIFIED with reason):**

- Any **live wireless, capture, or Bluetooth operation** — forbidden by the audit
  (no transmission, no hardware). All live paths are **UNVERIFIED at runtime** and
  assessed by source reading only.
- SIGINT → 130 runtime path — not exercised to avoid terminating a session; code
  path confirmed at `root.go:55,85`. **UNVERIFIED at runtime.**
- `make smoke`, `make lint`, race detector — not run (avoid state changes;
  `go vet` used as a safe substitute).

**Coverage observations (INFERRED):** the safety-critical core (operation
executor, lab harness, wireless parsing, WPA, credentials, rule builtins) is well
tested — a strong signal for a framework with hardware-gated behaviour.

---

## 14. Prioritized gaps and recommendations

| # | Priority | Gap | Why it matters | Recommended later action |
|---|---|---|---|---|
| G1 | **P1** | Shipped binary is an unstamped dev build (`commit:"none"`, `date:"unknown"`) | Provenance/reproducibility for orchestration & supply chain | Ensure release builds stamp ldflags; publish verifiable release |
| G2 | **P1** | Live wireless/BLE paths cannot be CI-verified without hardware | Regression risk in gated code | Expand `--sim`/fixture coverage so more paths run in CI |
| G3 | **P1** | Root `EXPLOITATION.md` duplicates `docs/` exploitation docs; mid-rename references | Documentation drift/confusion | Consolidate to one canonical doc (respecting the user's in-progress rename) |
| G4 | **P2** | `.github/workflows` has `ci.yml`, `tests.yml`, `release.yml` | Possible redundant CI | Confirm `tests.yml` isn't superseded by `ci.yml` |
| G5 | **P2** | `continue_A1.sh` and `PROMPT.md` at repo root | Stray development artifacts per layout conventions | Relocate/remove in a cleanup phase (do **not** touch now) |
| G6 | **P2** | `internal/errors`, `internal/config` duplicate kush's | Maintenance drift | Consider shared common-layer helpers |
| G7 | **P2** | Deauth/disassoc frames only reachable inside exploits | Offline/recon value of frame analysis under-exposed | Add read-only offline frame-summary commands |
| G8 | **P3** | `sessions/` runtime artifacts on disk (`0600`) | Potential sensitive data | Already gitignored; document retention/cleanup |
| G9 | **P3** | No bug-report linkage of findings to CWE beyond exploits | Analyst workflow | Add CWE mapping to WLAN rules |

---

## 15. Dependencies, prerequisites, unresolved questions

**Build/runtime dependencies (VERIFIED from `go.mod`):** Go 1.26.5 toolchain
(binary reports go1.27.1), `spf13/cobra`, `spf13/viper`, `muesli/termenv`,
`go.yaml.in/yaml/v3`, `golang.org/x/sys`, `golang.org/x/term`, and shared
`QYVORA/qyvora-script` v0.1.0, `QYVORA/qyvora-tui` v0.11.0. Runtime *system*
dependencies (not Go modules): the `iw` tool for interface discovery/scanning
(`transport/linux.go:127,336`), Linux `AF_PACKET`/`AF_BLUETOOTH` sockets, and
`CAP_NET_RAW` (`linux.go:77-79`; `bluetooth_controller_linux.go:85`).

**Hardware prerequisites:** a monitor-mode + injection-capable Wi-Fi adapter for
capture/active/exploit; a powered BLE/HCI adapter for BLE scan/GATT; root or
`CAP_NET_RAW`. `capabilities --hardware` reports which are actually present.

**Unresolved questions:**

1. Is the `EXPOLITATION.md` root↔docs duplication intended to converge on the
   in-progress `docs/EXPLOITATION-REFERENCE.md` rename? The rename is user work;
   its final intent is **UNVERIFIED**.
2. Are `ci.yml` and `tests.yml` meant to coexist, or is one legacy? **UNVERIFIED.**
3. Will live-path runtime behaviour (capture, BLE, active tests) be validated on
   real hardware in a later phase? Currently **UNVERIFIED at runtime** (audit
   forbade hardware I/O).
4. Is `continue_A1.sh` an intentional repo-root convenience or a stray to remove?
   **UNVERIFIED** — preserved as-is pending user direction.

---

## 16. No feature implementation was performed during this audit.

No feature was implemented, no command/module/rule was added, no code was
refactored, no dependency was introduced, no configuration changed, and no
existing file was modified. **In particular, every item of pre-existing
uncommitted user work listed in §12 was preserved untouched.** The **only** file
created by this audit is `AUDIT.md`. No wireless scan, frame transmission,
monitor-mode change, or hardware interaction was performed; all live operations
were refused by their own gates or deliberately not invoked. Every test and probe
run was non-destructive and read-only.
