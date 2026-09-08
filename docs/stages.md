# Pipeline stages

Mansa organizes assessment work into a strict, ordered pipeline. Every
full run (`assess` / `scan-all` / `run`) executes these stages in
order. Individual stages can also be invoked one-shot from the CLI or
console.

| #  | Stage       | What it does                                   |
|----|-------------|------------------------------------------------|
| 1  | **discover**| Detects wireless interfaces and capabilities    |
| 2  | **enumerate**| Scans for nearby access points                |
| 3  | **observe** | Collects associated client/station observations |
| 4  | **analyze** | Applies deterministic WLAN analysis rules      |
| 5  | **validate**| Validates and normalizes findings and data     |
| 6  | **findings**| Aggregates and deduplicates findings           |
| 7  | **risk**    | Computes risk scores and assigns risk level    |
| 8  | **report**  | Renders the requested output format            |

## One-shot vs. full pipeline

### One-shot

`mansa scan --sim` runs the stages up to and including `enumerate`. It
resolves the session, persists the collected data, and returns — no
findings or risk are computed.

### Full pipeline

`mansa assess --sim` runs all 8 stages. In the console, the `run`
command does the same.

### Re-analysis

`mansa analyze` loads an existing session from disk and runs **only**
`analyze → validate → findings → risk`, without re-scanning. This is
implemented internally as `RunStages([analyze, validate, findings, risk])`
so that discovery and enumeration data are not overwritten.

## Session lifecycle

At every stage, Mansa writes to the session's `Stages` slice, ensuring
the event log and stage list are always an exact trace of what ran.

## Events

Each stage emits two events: `stage.started` at entry, and either
`stage.completed` on success or `stage.completed` (with `level: error`)
on failure. The full event sequence for a successful `assess --sim`
contains exactly 17 entries:

```
scan.started
stage.started/discover   stage.completed/discover
stage.started/enumerate  stage.completed/enumerate
stage.started/observe    stage.completed/observe
stage.started/analyze    stage.completed/analyze
stage.started/validate   stage.completed/validate
stage.started/findings   stage.completed/findings
stage.started/risk       stage.completed/risk
stage.started/report     stage.completed/report
```

## Error handling

If any stage returns an error, the pipeline logs the failure in
`Session.Errors` and stops executing subsequent stages. The session is
still persisted to disk so that partial results are not lost.

Next: [Data collection](data-collection.md).