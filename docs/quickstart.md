# Quickstart

## Assessment

Run a full assessment in simulation mode:

```sh
mansa assess --sim
```

This discovers interfaces, scans for access points, observes stations,
runs the analysis rules, validates evidence, and computes risk scoring —
all without touching live wireless hardware.

## One-shot commands

Each pipeline stage is available as a standalone command. The flags
match the console commands exactly:

```sh
mansa discover --sim            # list simulated interfaces
mansa scan --sim                # AP scan
mansa enumerate --sim           # AP inventory with security
mansa observe --sim             # client/station observation
mansa analyze                   # analyze the latest session
mansa findings                  # show findings from the latest session
mansa evidence                  # show supporting evidence
mansa report -f markdown        # render a markdown report
mansa report -f json --out report.json  # JSON to file
```

## Interactive console

Start the console with no arguments:

```sh
mansa
```

Select an interface, optionally enable simulation, and run stages:

```
use wlan0
sim on
scan
analyze
findings
report --format markdown
exit
```

## JSON output

Pass `-o json` for machine-readable output on any command that supports it:

```sh
mansa capabilities -o json
mansa analyze -o json
mansa report -f json
```

## Finding events as JSONL

Append `--events` (or `--events stdout`) to any assessment command to
stream structured events. The envelope is identical on all events:

```json
{"schema_version":"1.0","timestamp":"...","execution_id":"...","framework":"mansa","level":"info","event":"scan.started","data":{...}}
```

## Piped / non-interactive usage

All commands can read `stdin` (for example, `yes` or a pre-built
prompt script) and default to non-interactive mode when they detect
a pipe.

Next: [Pipeline stages](stages.md).