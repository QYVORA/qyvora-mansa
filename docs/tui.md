# Shared terminal UI

Mansa uses the published `qyvora-tui` package. The TUI invokes Mansa through
the shared application/CLI path and consumes structured events and the
machine-readable capability registry. It is not a separate wireless UI, and it
does not scrape formatted terminal output. Mansa remains usable as a normal
CLI and through JSON/JSONL output without starting the TUI.

Current Mansa events include capture lifecycle, channel and temporary monitor
interface changes, live AP/client topology updates, BLE device observations,
and offline wireless authentication metadata. This repository has not had a
final end-to-end visual review against the latest qyvora-tui release. The
published TUI dependency has no license file in the inspected local module
cache; resolve its license provenance before distribution review is closed.
