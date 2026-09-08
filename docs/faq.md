# FAQ

## What is Mansa?

Mansa is QYVORA's terminal-first wireless security assessment framework.
It performs authorized wireless discovery, access-point enumeration,
client observation, WLAN security analysis, and channel/RF analysis, and
produces evidence-backed findings with transparent risk scoring.

## Is Mansa legal to use?

Mansa is a **authorized-use-only** tool. As with any wireless
assessment tool, using it requires a valid legal basis: assess networks
you own or are authorized to evaluate. Unauthorized scanning may be
unlawful in many jurisdictions. See [Authorization](authorization.md)
and the LICENSE.

## What is "simulation mode"?

`--sim` (or `sim on` in the console) runs the tool against a fixed,
deterministic dataset. No wireless hardware is contacted. It is useful
for learning, demos, and CI.

## What is the difference between `scan` and `assess`?

`scan` runs a single collection stage (`discover → enumerate`) and
returns data. `assess` (alias `scan-all`) runs the **full 8-stage
pipeline** through findings, risk, and report generation.

## What does the risk score mean?

The risk score is a deterministic 0–100 value computed as a weighted
mean of per-finding severity × confidence. See
[risk scoring](risk-scoring.md) for the exact formula.

## What does "latest session" mean?

Mansa resolves the "latest" session by the newest file modification
time in the session directory. See [sessions](sessions-and-evidence.md).

## Can I output JSON?

Yes. Pass `-o json` (or `json` as the console format). Machine-readable
output works on `analyze`, `findings`, `evidence`, `capabilities`,
`session`, `events`, `report -f json`, and the collection commands.

## Does Mansa support Windows?

Yes — it builds from source on Windows. Wireless live scanning is most
fully supported on Linux (via `iw`); on Windows use `--sim` or a
supported backend. `install.ps1` supports binary installs.

## How do I update Mansa?

`mansa updates` checks for and installs new releases, verifying the
SHA-256 checksum against the release manifest.

## Does Mansa upload any data?

No. Mansa is local-first: sessions, evidence, and reports are stored on
your machine. The only network access Mansa performs is contacting
GitHub (or your configured registry) for self-update checks.

## Where are sessions stored?

In `./sessions/` by default, override with `QYVORA_MANSA_SESSION_DIR`
or `session.dir` in the config file.

## Can I contribute?

Yes. See [Contributing](contributing.md).

Next: [Troubleshooting](troubleshooting.md).