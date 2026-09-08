# Sessions and evidence

Every Mansa assessment run is recorded as a **session** on disk. Sessions
are the primary persistence artifact and enable re-analysis, diffing,
auditing, and downstream tooling without re-collecting data.

## Session structure

A session is a self-contained JSON document:

```
<id>.session.json
```

Key fields:

| Field              | Meaning                                    |
|--------------------|--------------------------------------------|
| `id`               | Unique session identifier (`sess-<hex>`)   |
| `target`           | The declared assessment scope               |
| `interface`        | Wireless interface used (if any)            |
| `offline`          | Whether the session was collected in sim    |
| `start` / `end`    | Session timestamps                          |
| `stages`           | Ordered list of stages executed             |
| `errors`           | Stage-level errors (if any)                 |
| `access_points`    | Discovered APs                              |
| `stations`         | Observed client stations                    |
| `observations`     | RF and behavioral observations              |
| `findings`         | Evidence-backed security findings           |
| `evidence`         | Full evidence collection                    |
| `risk_score`       | Aggregate risk score (0–100)                |
| `risk_level`       | Human-readable risk label                   |

## Finding deduplication

`AddFinding()` deduplicates findings by fingerprint. The fingerprint
is a SHA-256 of the rule ID, category, title, and evidence key set.
When the same finding is produced twice (for example during
re-analysis), the existing entry is kept and its confidence is upgraded
to the highest observed value. Evidence sets are merged without
duplicates.

## Evidence deduplication

`AddEvidence()` deduplicates evidence by a content-based key
(`kind@source@target@detail`). Duplicate entries are silently dropped.

## Session directory

By default, sessions live in `./sessions/`. The directory is
configurable via `session.dir` in the config file or the environment
variable `QYVORA_MANSA_SESSION_DIR`.

The `latest` session is resolved by filesystem modification time. Both
the CLI `mansa analyze` (no `--session` flag) and the console `analyze`
command operate on the latest session by default.

## Re-analysis

`mansa analyze` loads an existing session and runs only the analysis
stages without re-collecting wireless data. This is safe, repeatable,
and produces a new risk score while preserving the original discovery
data. The stages appended are: `analyze, validate, findings, risk`.

## Events

Events are structured JSONL records emitted during assessment runs.
Each event shares a common envelope:

```json
{
  "schema_version": "1.0",
  "timestamp": "...",
  "execution_id": "...",
  "framework": "mansa",
  "level": "info|error",
  "event": "scan.started",
  "data": { ... }
}
```

Use `--events stdout`, `--events stderr`, or `--events /path/to/file`
on any assessment command to capture the stream. Use `mansa events` to
view events for the latest (or a specified) session.

Next: [Output and reporting](output-and-reporting.md).