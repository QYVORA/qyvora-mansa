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
  surface official QYVORA contact: https://qyvora.netlify.app ·
  qyvorasec@gmail.com · Tamale, Ghana.
- `--dry-run` plan output now routes to stderr when a machine-readable format
  is active, keeping stdout valid.
- Reports are written with mode 0600 in a 0700 directory (matching session
  artifacts) rather than 0644/0750.

### Added


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
