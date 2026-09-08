# Output and reporting

Mansa supports multiple output formats across all surfaces. The format
is chosen via `-o` (one-shot global flag) or `--format`/`-f` (on the
`report` command) and applies uniformly.

## Formats

| Format      | Flag value  | Description                                       |
|-------------|-------------|---------------------------------------------------|
| Terminal    | `terminal`  | Colorized, human-readable tables and summaries    |
| JSON        | `json`      | Structured machine-readable output                |
| YAML        | `yaml`      | Structured, human-editable output                 |
| Markdown    | `markdown`  | GitHub-flavored markdown tables                   |
| HTML        | `html`      | Standalone HTML document                          |

## Terminal output

The default format. Uses ANSI teal (`#00BAA3`) for headings, dim white
for values, and semantic icons (`+`, `!`, `•`) for status. No color
is emitted when stdout is not a TTY or when `NO_COLOR` is set.

## Machine-readable output

Pass `-o json` (or `json` to the console) for JSON output. This works
on commands that produce data: `analyze`, `findings`, `evidence`,
`capabilities`, `version`, `session`, `events`, `discover`, `scan`,
`enumerate`, `observe`, and the full `assess` pipeline.

Example with `jq`:

```sh
mansa analyze -o json | jq '.findings[] | select(.severity == "critical")'
mansa session -o json | jq '.[0]'
mansa capabilities -o json | jq '.[] | .id'
```

## Report command

`mansa report` renders a formatted report from the current or specified
session:

```sh
mansa report -f terminal                     # default: rich terminal table
mansa report -f markdown --out report.md     # write markdown to file
mansa report -f json                         # JSON to stdout
mansa report -f html --out report.html       # standalone HTML report
```

The `report` flags:

| Flag       | Meaning                                      |
|------------|----------------------------------------------|
| `-f`       | Output format (default: `terminal`)          |
| `--out`    | Write report to this file instead of stdout  |

## Console output

Inside the console, the active output format is set by passing a format
to `sim on`, or by passing `-o` before entering the console. The
`report` command respects `--format` (console form of the one-shot
`-f`).

## Events (JSONL)

Events are emitted as newline-delimited JSON. They can be captured on
any command via `--events`:

```sh
mansa assess --sim --events events.jsonl       # write to file
mansa assess --sim --events stdout | jq -c .   # stream to jq
mansa assess --sim --events stderr              # mix with stderr
```

The `events` envelope is always schema-versioned and framework-tagged,
so it is safe to merge streams from different QYVORA tools.

Next: [Settings](settings.md).