# CLI Reference

`mansa` is a one-shot command-line tool. Every command follows the
shared QYVORA tier grammar:

```
mansa <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon` (discovery, collection, enumeration and
analysis), `exploit` (active testing and exploitation), or `report`
(findings, evidence and reports). Running `mansa` with no
arguments prints this help. Every pre-tier command remains available as
a hidden alias, so existing scripts keep working.

Exit codes: `0` success &middot; `1` runtime failure &middot; `2` usage error
&middot; `3` unsupported target &middot; `130` interrupted.

## recon

Discovery, collection, enumeration and analysis modules.

| Command | Purpose |
|---------|---------|
| `mansa recon analyze` | Analyze the latest session for security findings |
| `mansa recon assess` | Run the full wireless assessment pipeline |
| `mansa recon bluetooth` | Bluetooth and BLE analysis |
| `mansa recon capture` | Capture live wireless frames or analyze offline capture files |
| `mansa recon credentials Assess captured WPA/WPA2 handshake material against candidate passphrases` | — |
| `mansa recon discover` | Discover wireless interfaces and capabilities |
| `mansa recon enumerate` | Enumerate access-point inventory with filtering |
| `mansa recon events` | Show stored events for a session |
| `mansa recon observe` | Observe wireless clients/stations and observations |
| `mansa recon scan` | Scan for wireless networks and access points |
| `mansa recon session` | Inspect saved sessions |
| `mansa recon target` | Manage assessment targets |
| `mansa recon validate` | Run validation modules: confirm or refute an observed condition from collected data |

## exploit

Active-testing and exploitation modules.

| Command | Purpose |
|---------|---------|
| `mansa exploit exploit` | Run exploitation modules: drive an authorized laboratory target toward a known outcome |
| `mansa exploit test` | Run active-test modules: transmit a bounded, declared frame set at an authorized target |

## report

Findings, evidence and report rendering.

| Command | Purpose |
|---------|---------|
| `mansa report evidence` | Show evidence collected in a session |
| `mansa report findings` | Show findings from a session |

## Utilities

| Command | Purpose |
|---------|---------|
| `mansa capabilities List the machine-readable capability contract` | — |

## Global flags

| Flag | Purpose |
|------|---------|
| `-y, --authorized      confirm authorization scope non-interactively` | — |
| `--dry-run         show the assessment plan without executing` | — |
| `--events string   emit JSONL event stream to stdout, stderr, or a file path` | — |
| `-h, --help            help for mansa` | — |
| `--no-tui          Disable TUI and print banner/help` | — |
| `-o, --output string   output format: terminal, json, yaml, markdown, html` | — |
| `--quiet           suppress non-error output` | — |
| `--update          update the CLI to the latest official release` | — |
| `-v, --verbose         verbose output` | — |
| `--version         version for mansa` | — |

