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
target        Manage assessment targets
capabilities  List the machine-readable capability contract
version       Print version information
updates       Check for and install Mansa updates
completion    Generate shell completion scripts
```

Global flags: `-o/--output`, `-y/--authorized`, `-v/--verbose`,
`-q/--quiet`, `--events`, `--dry-run`.

## Documentation

- [Introduction](docs/introduction.md)
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

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.netlify.app · Security/Support: qyvorasec@gmail.com

## License

[MIT](LICENSE)

**Authorized use only.** Assess wireless networks you own or are
authorized to evaluate.