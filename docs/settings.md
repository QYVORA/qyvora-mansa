# Settings

Mansa configuration is layered: **compiled defaults → config file →
environment variables → command-line flags**. The last source wins.

## Config file search

Mansa looks for `config.yaml` (YAML format) in, in order:

1. Current working directory
2. `~/.qyvora-mansa/`
3. `~/.config/qyvora/mansa/`
4. `/etc/qyvora-mansa/`

A malformed file is an error; a missing file is not. An explicit path
can be supplied where supported.

## Environment variables

All config keys are overridable via environment variables. The prefix is
`QYVORA_MANSA_`; dots (`.`) and dashes (`-`) are replaced by
underscores (`_`):

| Config key                     | Environment variable                              | Default  |
|--------------------------------|---------------------------------------------------|----------|
| `authorized`                   | `QYVORA_MANSA_AUTHORIZED`                         | `false`  |
| `output`                       | `QYVORA_MANSA_OUTPUT`                             | `terminal` |
| `verbose`                      | `QYVORA_MANSA_VERBOSE`                            | `false`  |
| `quiet`                        | `QYVORA_MANSA_QUIET`                              | `false`  |
| `report.dir`                   | `QYVORA_MANSA_REPORT_DIR`                         | `reports` |
| `report.format`                | `QYVORA_MANSA_REPORT_FORMAT`                      | `terminal` |
| `session.dir`                  | `QYVORA_MANSA_SESSION_DIR`                        | `""` (./sessions) |
| `log.level`                    | `QYVORA_MANSA_LOG_LEVEL`                          | `info`   |
| `wireless.interface`           | `QYVORA_MANSA_WIRELESS_INTERFACE`                 | `""`     |
| `wireless.timeout_seconds`     | `QYVORA_MANSA_WIRELESS_TIMEOUT_SECONDS`           | `30`     |
| `analysis.confidence_threshold`| `QYVORA_MANSA_ANALYSIS_CONFIDENCE_THRESHOLD`      | `medium` |

## Flag overrides

Every global flag (`-o`, `-v`, `-q`, `-y`, `--dry-run`, `--events`)
overrides both the config file and environment for that run.

## Minimal example

```yaml
# ~/.qyvora-mansa/config.yaml
wireless:
  interface: wlan1
  timeout_seconds: 15
output: json
verbose: true
```

Override a single value for one run:

```sh
QYVORA_MANSA_VERBOSE=false mansa assess --sim
```

## Defaults validation

Mansa validates known keys at startup. An unrecognized key in the
config file does not produce an error but is silently ignored. The
`analysis.confidence_threshold` value is validated against the
recognized set: `possible`, `probable`, `observed`, `confirmed`.

Next: [Authorization](authorization.md).