Yes. The important distinction is that **Mansa should become a Go-native wireless security framework**, not a wrapper around Aircrack-ng. I checked the current `QYVORA/qyvora-mansa` repository: it is already a Go WLAN assessment framework, MIT-licensed, and currently centered on discovery, AP enumeration, configuration analysis, authentication assessment, and traffic analysis. [QYVORA/qyvora-mansa](https://github.com/QYVORA/qyvora-mansa?utm_source=chatgpt.com)

One correction before the prompt: **Apple Core Bluetooth is not a Linux Bluetooth hacking framework**. It's Apple's Bluetooth API. For Mansa's Linux-side Bluetooth implementation, the important reference architecture is **BlueZ/kernel Bluetooth APIs**, with other research tools used as capability references. Similarly, Aircrack-ng is broader than the list you gave: its documented suite includes `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`, `airbase-ng`, `airdecap-ng`, `airdecloak-ng`, `packetforge-ng`, `airolib-ng`, `airserv-ng`, `airgraph-ng`, `airdrop-ng`, `airtun-ng`, and others. ([Aircrack-ng][1])

And SecLists is actually **`SecLists`** upstream, although your local directory being `seclists` is perfectly fine. It contains passwords, usernames, discovery lists, payloads, fuzzing material, etc. ([GitHub][2])

Here is the prompt I would give the coding AI.

---

# MASTER IMPLEMENTATION PROMPT: QYVORA MANSA WIRELESS SECURITY ENGINE EXPANSION

```text
You are working directly inside the QYVORA MANSA repository.

Repository:
QYVORA/qyvora-mansa

MANSA is QYVORA's Go-native wireless security assessment framework.

IMPORTANT:
Do not treat this as a wrapper project.
Do not simply shell out to Aircrack-ng, BlueZ utilities, Nmap, Bettercap, or other external security tools for the core implementation.

The objective is to evolve MANSA into a serious, modular, Go-native wireless security framework whose architecture is capable of progressing from:

DISCOVER
→ ENUMERATE
→ OBSERVE
→ ANALYZE
→ VALIDATE
→ ASSESS
→ EXPLOITATION
→ EVIDENCE
→ FINDINGS
→ RISK
→ REPORT

The framework must support Wi-Fi/WLAN and Bluetooth/BLE as first-class wireless domains.

==================================================
0. FIRST: AUDIT THE EXISTING QYVORA ARCHITECTURE
==================================================

Before changing code, inspect the entire MANSA repository.

Understand:

- existing Go module
- cmd/
- internal/
- pkg/
- current WLAN models
- discovery pipeline
- observation pipeline
- analysis engine
- validation engine
- findings
- risk engine
- evidence handling
- output/event system
- JSON/JSONL contracts
- simulation mode
- tests
- CLI
- current TUI integration
- capability declarations
- documentation
- build/release configuration

Do NOT throw away existing working architecture.

Extend it.

Preserve backward compatibility wherever practical.

MANSA already follows a structured security-assessment architecture. Expand that architecture rather than replacing it with unrelated subsystems.

==================================================
1. QYVORA SHARED COMPONENTS
==================================================

MANSA must integrate with the QYVORA architecture.

Inspect and use:

1. qyvora-common
2. qyvora-tui

Do not invent competing event models if an existing QYVORA contract already provides the required behavior.

The shared TUI must consume structured events.

DO NOT scrape terminal output.

The underlying MANSA engine must remain usable without the TUI.

Architecture:

CLI
  ↓
MANSA application/service layer
  ↓
capability modules
  ↓
wireless platform adapters
  ↓
kernel / hardware interfaces
  ↓
structured events
  ↓
TUI / JSONL / files / reports

The same execution engine must power:

- normal CLI
- JSON
- JSONL
- TUI
- simulation mode
- future AI orchestration

==================================================
2. CORE DESIGN PRINCIPLE
==================================================

Do NOT translate Aircrack-ng source code line-by-line into Go.

Instead:

Study the documented capabilities and underlying concepts of mature wireless-security tooling.

Then implement equivalent MANSA-native capabilities using idiomatic Go and appropriate Linux/kernel interfaces.

Aircrack-ng is a reference capability set, not MANSA's implementation architecture.

Reference capabilities include:

- wireless interface discovery
- monitor-mode management
- channel management
- 802.11 frame capture
- frame parsing
- AP discovery
- station discovery
- BSSID/ESSID relationships
- beacon/probe analysis
- authentication analysis
- packet filtering
- frame injection support
- replay/testing capabilities
- capture management
- WPA/WPA2 assessment
- WEP assessment
- capture-file processing
- packet decoding
- wireless traffic analysis
- fake AP/lab assessment capabilities
- packet construction
- radio capability detection

Aircrack-ng's official documentation describes monitoring, packet capture, injection/replay, testing, and WEP/WPA-PSK assessment as core areas. Use that as a capability reference. 

Do not copy implementation code unless its license permits it and attribution/license requirements have been explicitly handled.

==================================================
3. MANSA WIRELESS ARCHITECTURE
==================================================

Create a clear internal abstraction such as:

WirelessProvider

with implementations/adapters for:

- Linux WLAN
- Linux Bluetooth
- simulation

Potential conceptual interfaces:

WirelessDevice
WirelessInterface
WirelessCapture
WirelessFrame
WirelessChannel
WirelessInjector
WirelessSession
WirelessCapability
WirelessEvidence

Do not blindly copy these names if the repository already has better abstractions.

The abstraction must allow multiple physical interfaces.

Example conceptual model:

MANSA
 ├── WLAN
 │    ├── interface management
 │    ├── monitor mode
 │    ├── channel control
 │    ├── capture
 │    ├── frame parsing
 │    ├── analysis
 │    ├── validation
 │    └── authorized testing modules
 │
 └── Bluetooth
      ├── adapter management
      ├── discovery
      ├── BLE discovery
      ├── device enumeration
      ├── service enumeration
      ├── GATT analysis
      ├── protocol analysis
      ├── validation
      └── authorized testing modules

==================================================
4. WI-FI / 802.11 ENGINE
==================================================

Implement a real WLAN engine.

Capabilities should include:

INTERFACE MANAGEMENT

- enumerate wireless interfaces
- detect chipset information
- detect driver information
- detect supported bands
- detect supported channels
- detect monitor-mode capability
- detect injection capability where safely testable
- managed/monitor interface state
- interface lifecycle
- channel configuration
- interface restoration

MONITOR MODE

Provide a native MANSA interface-management layer capable of:

- detecting monitor-mode support
- creating/enabling monitor-mode interfaces where supported
- restoring interfaces
- tracking the original interface state
- handling failures cleanly
- avoiding permanent network configuration damage

Do not assume every adapter supports every capability.

Capabilities must be detected dynamically.

==================================================
5. 802.11 FRAME CAPTURE
==================================================

Implement a high-performance capture engine.

Support parsing and classification of relevant 802.11 frame categories:

- management
- control
- data

And important management subtypes such as:

- beacon
- probe request
- probe response
- authentication
- association
- reassociation
- disassociation
- deauthentication
- action

Create structured frame models.

Avoid repeatedly allocating memory for every packet.

Use:

- reusable buffers
- bounded queues
- worker pools
- streaming parsers
- zero-copy techniques where practical
- preallocated structures
- efficient MAC-address representation
- compact frame metadata

Do NOT use concurrency blindly.

Benchmark every performance-sensitive subsystem.

==================================================
6. HIGH PERFORMANCE ENGINE
==================================================

MANSA must be designed for high packet rates.

Study the performance characteristics of mature packet-processing systems.

Use appropriate techniques including:

- goroutines
- worker pools
- bounded channels
- batching
- buffer reuse
- sync.Pool where appropriate
- efficient hash maps
- compact structures
- bit masks
- bit-level parsing
- reduced allocations
- streaming processing
- backpressure
- packet filtering before expensive parsing
- CPU affinity only where justified
- efficient timestamps
- avoiding unnecessary string conversions
- avoiding repeated MAC address formatting
- avoiding unnecessary JSON serialization inside hot loops

Separate:

HOT PATH

from:

CONTROL PATH

The packet hot path should perform the minimum work necessary.

Architecture:

NIC / kernel
    ↓
capture
    ↓
fast filter
    ↓
frame parser
    ↓
normalized event
    ↓
analysis workers
    ↓
evidence/findings

Do not run expensive analysis synchronously on every packet.

==================================================
7. CHANNEL AND RADIO MANAGEMENT
==================================================

Implement channel-management abstractions.

Support:

- channel enumeration
- channel switching
- band detection
- channel hopping
- fixed-channel capture
- multi-interface capture
- channel scheduling

The scheduler should support:

- dwell time
- priority
- target-specific channels
- configurable hopping
- cancellation
- restoration

Do not hardcode assumptions about regulatory domains.

Respect the host's available wireless capabilities.

==================================================
8. WI-FI DISCOVERY ENGINE
==================================================

MANSA should build a continuously updated wireless topology model.

Track:

ACCESS POINT

- BSSID
- ESSID
- channel
- band
- security mode
- cipher
- authentication
- signal information when available
- first seen
- last seen
- vendor/OUI
- beacon metadata
- supported rates
- capabilities
- observed clients

CLIENT

- station MAC
- associated BSSID
- first seen
- last seen
- signal information
- observed management activity

RELATIONSHIP GRAPH

AP
 ↕
CLIENT

Include:

- hidden ESSID observations
- multiple BSSIDs
- roaming relationships
- duplicate observations
- vendor information

Use deterministic identifiers.

==================================================
9. SECURITY ANALYSIS
==================================================

Implement analysis for wireless configuration and protocol weaknesses.

Examples:

- open networks
- weak legacy security
- WEP
- WPA
- WPA2
- WPA3
- insecure configuration combinations
- weak management-frame protection configurations
- suspicious AP behavior
- rogue AP indicators
- duplicate/evil-twin indicators
- anomalous beacon behavior
- insecure channel/configuration patterns
- client exposure
- protocol downgrade indicators
- insecure legacy compatibility modes

Findings must be deterministic.

Every finding should contain:

- ID
- title
- severity
- confidence
- affected target
- evidence
- detection logic
- remediation
- references

==================================================
10. CAPTURE / PCAP ENGINE
==================================================

Implement native capture processing.

Support:

- capture sessions
- PCAP/PCAPNG where practical
- capture metadata
- frame indexing
- filtering
- replay-independent analysis
- evidence extraction
- capture statistics

Provide efficient offline analysis.

A capture should be analyzable without a live wireless adapter.

==================================================
11. WI-FI VALIDATION / AUTHENTICATION ASSESSMENT
==================================================

Implement authorized security-validation capabilities.

The architecture must support assessment of:

- authentication exchanges
- handshake-related observations
- PMKID-related observations
- WEP-related capture conditions
- WPA/WPA2 authentication metadata
- WPA3/SAE observations
- enterprise authentication observations

Separate:

OBSERVATION

from:

VALIDATION

from:

ACTIVE TESTING

from:

EXPLOITATION

Do not make active testing indistinguishable from passive discovery.

==================================================
12. ACTIVE WIRELESS TESTING ENGINE
==================================================

Create an explicit active-testing subsystem.

Capabilities should be represented as modules.

Examples:

- frame injection capability detection
- controlled frame transmission
- replay testing
- authentication testing
- management-frame validation
- AP/client behavior validation
- packet-construction testing
- protocol robustness testing

Every active module must have:

- capability declaration
- required hardware
- required privileges
- target requirements
- authorization state
- safety classification
- simulation support
- evidence output
- cancellation support

Do not bury active behavior inside the passive scanner.

==================================================
13. EXPLOITATION ARCHITECTURE
==================================================

MANSA must have an exploitation layer.

Do NOT implement exploitation as arbitrary shell commands.

Create an explicit exploitation framework.

Conceptually:

ExploitRegistry
Exploit
ExploitMetadata
ExploitPrerequisites
ExploitExecutor
ExploitResult
ExploitEvidence

Every exploit should declare:

- exploit ID
- affected protocol/component
- vulnerability class
- prerequisites
- required privileges
- required hardware
- target type
- expected evidence
- cleanup requirements
- simulation availability

The execution engine must enforce explicit target authorization and scope.

For development, use controlled lab targets and simulation fixtures to validate exploit modules.

Do not place destructive or indiscriminate behavior in default execution paths.

==================================================
14. BLUETOOTH / BLE ENGINE
==================================================

Bluetooth must be a first-class MANSA subsystem.

IMPORTANT:

Do not use Apple Core Bluetooth as the Linux implementation.

Core Bluetooth is Apple's API.

For Linux, investigate:

- BlueZ
- Linux Bluetooth kernel interfaces
- HCI
- BLE/GATT primitives
- appropriate raw or management interfaces

Implement a MANSA-native abstraction over those interfaces.

==================================================
15. BLUETOOTH CAPABILITIES
==================================================

Implement:

ADAPTER DISCOVERY

- enumerate Bluetooth adapters
- adapter state
- address
- supported capabilities
- supported modes
- power state

CLASSIC BLUETOOTH DISCOVERY

- device discovery
- address
- device class
- name
- manufacturer information where available
- signal information where available

BLE DISCOVERY

- advertisements
- manufacturer data
- service UUIDs
- device identifiers
- RSSI
- advertising intervals where available
- beacon identification

GATT

Implement structured discovery of:

- services
- characteristics
- descriptors
- properties
- handles
- UUIDs

Provide a normalized MANSA representation.

==================================================
16. BLUETOOTH SECURITY ANALYSIS
==================================================

Analyze:

- insecure pairing configurations
- legacy protocol exposure
- discoverability
- weak configuration
- exposed GATT services
- dangerous characteristic properties
- unauthenticated access
- missing authorization
- sensitive information exposed through advertisements
- insecure BLE service design
- suspicious Bluetooth behavior

Create deterministic findings.

==================================================
17. BLUETOOTH ACTIVE TESTING
==================================================

Create an explicit Bluetooth testing layer.

Support authorized laboratory testing of:

- pairing behavior
- service exposure
- GATT authorization
- malformed-input handling
- protocol robustness
- connection behavior
- security-control validation

Use test fixtures and controlled devices for automated tests.

Do not make arbitrary nearby-device interaction the default behavior.

==================================================
18. WIRELESS PROTOCOL MODULE SYSTEM
==================================================

Create a plugin-like internal capability registry.

Concept:

Capability
 ├── ID
 ├── Domain
 ├── Description
 ├── Requirements
 ├── Privileges
 ├── Hardware
 ├── Active/Passive
 ├── Risk classification
 ├── Simulation support
 └── Executor

Domains:

wifi
bluetooth
ble
80211
hci
gatt
authentication
capture
analysis
validation
exploitation

This registry will later be consumed by the QYVORA AI orchestration layer.

==================================================
19. WORDLIST / DATA ASSETS
==================================================

There is a local SecLists installation available on the development machine.

Search the local filesystem for the actual location.

DO NOT assume the directory name.

The upstream project is commonly named:

SecLists

The local installation may use:

seclists

Inspect it.

Identify useful categories relevant to wireless security testing.

Do NOT blindly embed the entire SecLists repository.

Instead:

1. inventory it
2. identify relevant datasets
3. identify licensing
4. identify size
5. identify duplication
6. select appropriate subsets
7. create MANSA-owned curated assets

The final binary should have useful built-in datasets.

However, users must ALSO be able to provide external wordlists.

Architecture:

Built-in wordlists
+
external user wordlists
+
generated candidates
+
custom dictionaries

Use Go's embed facilities where appropriate.

Avoid enormous default binaries.

Provide:

--wordlist
--wordlist-dir
and an internal/default mode.

The default mode should work without the user manually hunting for files.

==================================================
20. CRACKING / PASSWORD ASSESSMENT ARCHITECTURE
==================================================

Create a modular password-assessment engine.

Separate:

candidate generation
candidate loading
candidate filtering
credential verification
result handling

Use streaming rather than loading massive lists entirely into memory.

Support:

- built-in dictionaries
- external dictionaries
- generated candidates
- rule-based mutation
- configurable limits
- cancellation
- progress events
- deterministic testing

Do not claim a password was cracked unless the verification condition is actually satisfied.

Every result must include evidence.

==================================================
21. PERFORMANCE ENGINEERING
==================================================

Benchmark:

- packet parsing
- frame classification
- MAC lookup
- AP/client correlation
- channel scheduling
- capture ingestion
- PCAP processing
- Bluetooth advertisement parsing
- GATT discovery
- candidate processing

Add benchmarks.

Measure:

- packets/sec
- allocations/op
- bytes/op
- CPU utilization
- memory
- queue latency

Use:

go test -bench
pprof
race detector
fuzz tests

Do not optimize based on intuition.

Measure first.

==================================================
22. CONCURRENCY MODEL
==================================================

Do NOT simply add goroutines everywhere.

Use a deliberate model:

Capture goroutine(s)
        ↓
bounded ingestion queue
        ↓
parser workers
        ↓
analysis workers
        ↓
aggregation
        ↓
evidence
        ↓
events

Provide:

- cancellation
- deadlines
- backpressure
- bounded memory
- graceful shutdown
- worker lifecycle management

No goroutine leaks.

Every long-running operation must respond to context cancellation.

Map cancellation consistently according to QYVORA's existing CLI conventions.

==================================================
23. STRUCTURED EVENTS
==================================================

Every operation must emit structured events.

Do not make the TUI parse human-readable strings.

Events should cover:

device discovered
interface changed
channel changed
capture started
capture stopped
frame observed
AP discovered
client discovered
Bluetooth device discovered
GATT service discovered
analysis started
finding created
validation started
validation completed
active test started
active test completed
exploit started
exploit completed
evidence created
error
warning
progress
cancellation

Use the existing QYVORA event contract.

==================================================
24. EVIDENCE
==================================================

Every important security result must be reproducible.

Evidence may include:

- timestamps
- interface
- channel
- BSSID
- station
- frame metadata
- capture references
- hashes
- Bluetooth advertisement data
- GATT metadata
- test results
- execution IDs

Avoid storing unnecessary sensitive information.

Make evidence exportable.

==================================================
25. SIMULATION MODE
==================================================

MANSA already has simulation capabilities.

Expand them.

Every major capability should have simulated fixtures.

Examples:

- simulated AP
- simulated client
- simulated beacon
- simulated handshake metadata
- simulated BLE advertisement
- simulated GATT database
- simulated vulnerability
- simulated validation
- simulated exploit result

This allows CI to test MANSA without wireless hardware.

==================================================
26. HARDWARE ABSTRACTION
==================================================

Never assume a particular Wi-Fi chipset.

Create hardware capability detection.

Example:

CAPTURE
INJECTION
MONITOR_MODE
CHANNEL_SWITCH
2.4GHZ
5GHZ
6GHZ
BLE
CLASSIC_BT

Report unsupported functionality honestly.

Never silently pretend functionality succeeded.

==================================================
27. CLI
==================================================

Create a clean command structure.

Conceptually:

mansa
  wireless
    wifi
      interfaces
      monitor
      discover
      capture
      analyze
      validate
      test
    bluetooth
      adapters
      discover
      ble
      gatt
      analyze
      validate
      test

But inspect the existing CLI before changing it.

Do not unnecessarily break existing commands.

Capability discovery should be possible.

Example conceptual command:

mansa capabilities

should report what the current machine and MANSA build support.

==================================================
28. TUI
==================================================

Integrate with qyvora-tui.

The TUI should expose:

- current wireless interface
- capture state
- channel
- discovered APs
- discovered clients
- Bluetooth devices
- active operations
- findings
- evidence
- progress
- errors
- execution steps

Use the existing QYVORA terminal-native design system.

Do not build a web dashboard.

Do not create a second TUI framework.

==================================================
29. AI ORCHESTRATION READINESS
==================================================

MANSA will eventually be one component in a larger QYVORA AI orchestration layer.

Therefore:

Every capability must be machine-readable.

The AI must be able to discover:

- capability ID
- description
- requirements
- inputs
- outputs
- supported platforms
- hardware requirements
- risk classification
- passive/active status
- simulation availability

Example conceptual structure:

{
  "id": "wifi.capture",
  "domain": "wifi",
  "mode": "passive",
  "requires": ["monitor_mode"],
  "hardware": ["80211_adapter"],
  "outputs": ["frames", "evidence"]
}

Do not hardcode this exact schema if QYVORA already has a capability contract.

==================================================
30. DOCUMENTATION
==================================================

Update all relevant documentation.

At minimum:

README
ARCHITECTURE
CAPABILITIES
WIRELESS
BLUETOOTH
PERFORMANCE
TESTING
HARDWARE
TUI
EVENTS
EVIDENCE
SECURITY MODEL

Document what is:

- implemented
- partially implemented
- hardware-dependent
- Linux-only
- simulation-only
- unavailable

Never document planned functionality as implemented.

==================================================
31. TESTING REQUIREMENTS
==================================================

Add:

unit tests
integration tests
parser tests
fuzz tests
benchmark tests
simulation tests
event-contract tests
cancellation tests
hardware-adapter tests where possible

Test:

- malformed frames
- truncated packets
- invalid MAC addresses
- malformed information elements
- malformed BLE advertisements
- invalid GATT structures
- high packet rates
- queue saturation
- cancellation
- concurrent sessions
- interface failures

Run:

go test ./...
go vet ./...
go test -race ./...

Add benchmarks.

==================================================
32. SECURITY AND AUTHORIZATION MODEL
==================================================

MANSA is an offensive-security framework.

Do not remove the offensive-testing architecture.

Instead, make active operations explicit and auditable.

The framework must distinguish:

PASSIVE
ACTIVE_TEST
VALIDATION
EXPLOITATION

Operations that can affect third-party wireless infrastructure must require an explicit authorized testing context.

The authorization context should be represented in the execution/session model rather than scattered across individual functions.

Every active operation should have:

- target
- scope
- authorization state
- execution ID
- timestamp
- operator/session metadata where appropriate
- evidence
- cleanup state

Simulation mode must remain available for development and CI.

==================================================
33. EXTERNAL PROJECT RESEARCH
==================================================

Before implementing each subsystem, study mature projects for:

- functionality
- protocol behavior
- data structures
- performance approaches
- hardware requirements
- kernel interfaces
- edge cases

Relevant reference categories include:

Aircrack-ng
BlueZ
Linux wireless stack
Linux Bluetooth stack
Wireshark/tshark
Kismet
Bettercap
hostapd
wpa_supplicant
appropriate Bluetooth/BLE research tools

These are REFERENCE IMPLEMENTATIONS.

Do not blindly reproduce their source code.

Do not turn MANSA into a collection of shell wrappers.

Extract concepts and implement the MANSA architecture in Go.

==================================================
34. LICENSE / ATTRIBUTION AUDIT
==================================================

Before incorporating any external:

- algorithm
- source code
- wordlist
- dataset
- protocol definition
- generated asset

check its license.

Create an attribution document where required.

Do not copy GPL/source material into an MIT project without determining the licensing consequences.

This is mandatory.

==================================================
35. IMPLEMENTATION ORDER
==================================================

Do NOT attempt to implement everything in one giant unstructured change.

Implement in architectural phases:

PHASE 1
Repository audit and architecture update.

PHASE 2
Hardware capability abstraction.

PHASE 3
Wi-Fi interface management.

PHASE 4
Monitor mode and channel management.

PHASE 5
High-performance 802.11 capture engine.

PHASE 6
802.11 parser and normalized frame model.

PHASE 7
AP/client discovery and topology.

PHASE 8
Wireless security analysis.

PHASE 9
PCAP/evidence engine.

PHASE 10
Wi-Fi validation and authorized active-testing framework.

PHASE 11
Bluetooth adapter abstraction.

PHASE 12
Bluetooth/BLE discovery.

PHASE 13
GATT enumeration and analysis.

PHASE 14
Bluetooth validation/testing framework.

PHASE 15
Password/data asset subsystem.

PHASE 16
Exploitation framework architecture.

PHASE 17
TUI integration.

PHASE 18
AI capability manifest.

PHASE 19
Performance optimization.

PHASE 20
Full test/benchmark/documentation pass.

==================================================
36. DEFINITION OF DONE
==================================================

Do not stop after creating interfaces or placeholders.

A feature is complete only when:

- implementation exists
- CLI integration exists
- structured events exist
- TUI integration exists where applicable
- simulation exists where practical
- tests exist
- documentation exists
- capability metadata exists
- errors are handled
- cancellation works
- evidence is generated
- unsupported hardware is reported honestly

Do not create fake implementations that simply return:

"not implemented"

while claiming the feature exists.

==================================================
37. FINAL AUDIT
==================================================

After implementation:

1. inspect the complete repository
2. identify duplicated abstractions
3. identify dead code
4. identify race conditions
5. run tests
6. run vet
7. run benchmarks
8. run race detector
9. inspect allocations in hot paths
10. verify TUI integration
11. verify JSON/JSONL
12. verify simulation
13. verify capability manifest
14. verify documentation
15. verify license/attribution
16. verify that active operations cannot accidentally execute against an unspecified target

Then produce:

MANSA_IMPLEMENTATION_AUDIT.md

containing:

- implemented capabilities
- architecture changes
- hardware requirements
- performance measurements
- test results
- unsupported capabilities
- known limitations
- licensing decisions
- remaining work

IMPORTANT:

Do not rewrite the repository merely to make the architecture look different.

Preserve working MANSA functionality.

Extend it systematically.

The final product must feel like one coherent QYVORA framework, not Aircrack-ng + BlueZ + random scripts glued together with Go.

MANSA owns the architecture.

Go owns the implementation.

QYVORA owns the event/capability/TUI integration.

The underlying Linux wireless and Bluetooth subsystems provide the hardware interface.

The result should be a serious wireless security framework capable of moving from reconnaissance through analysis, validation, authorized active testing, and exploitation while producing structured evidence throughout the entire lifecycle.
```

### One thing I'd change from your original plan

Don't put **the entire SecLists repository inside the binary**. That's how you eventually create a magnificent 900 MB security Swiss Army knife because apparently humanity enjoys making binaries enormous.

Use a **curated MANSA asset pack** instead:

```text
internal/assets/
├── wifi/
│   ├── common-ssids.txt
│   ├── common-passwords.txt
│   └── vendors.txt
├── bluetooth/
│   ├── uuids.txt
│   └── device-names.txt
└── generated/
    └── ...
```

Then use Go `embed` for the compact defaults, while still supporting external wordlists.

Also, the Aircrack capabilities you've identified are real: `airmon-ng` handles monitor-mode management, `airodump-ng` captures raw 802.11 frames, `aireplay-ng` handles frame injection/replay, and `aircrack-ng` handles WEP/WPA-PSK cracking. ([Aircrack-ng][3])

The key architectural idea is **not "make Mansa a Go version of every Aircrack binary."** It's **"make Mansa own the underlying capability model."** Then `wifi.capture`, `wifi.monitor`, `wifi.inject`, `wifi.auth-assess`, `ble.discover`, `ble.gatt`, `wireless.analyze`, etc. become capabilities that the future QYVORA orchestration layer can discover and compose.

