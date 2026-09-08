# Simulation vs. Live mode

## `--sim` (simulation)

The `--sim` flag bypasses all live wireless calls and uses a fixed,
deterministic dataset designed to exercise every analysis rule. No
wireless hardware or root privileges are required.

In the console, use `sim on` or `sim off` to toggle the same mode
at any time.

**Key properties of simulation mode:**

- Fully deterministic: two runs with the same interface produce
  identical access points, stations, observations, and findings.
- Authorized by default — no confirmation is needed.
- Works offline and is suitable for CI pipelines, scripted smoke
  testing, and environments without wireless radios.

## Live mode (default)

Without `--sim`, Mansa issues real wireless data collection calls:

- `discover` → `iw dev` (Linux)
- `enumerate` → `iw dev <iface> scan` (Linux)

Live mode requires:

- Root or appropriate capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`)
- `iw` (or a supported backend) available on `PATH`
- Authorization confirmed (`-y` / `--authorized` or `authorize`)

When authorization is not confirmed and a live command is requested,
Mansa exits with an informative message.

## Interface selection

| Surface | Selection |
|---------|-----------|
| CLI     | `--interface wlan0` |
| Console | `use wlan0` |
| Config  | `wireless.interface: wlan0` |

The interface is resolved in that priority order. If `--sim` is active,
the selected interface is still recorded in the session metadata so
reports can be filtered later.

## Scanner flags (shared)

The following flags are available on the CLI commands `assess`, `scan`,
`enumerate`, `observe`, and in the console equivalents:

| Flag         | Meaning                                  |
|--------------|------------------------------------------|
| `--interface`| wireless interface to use               |
| `--sim`      | use deterministic simulation dataset    |
| `--band`     | filter results to a band (2.4/5/6 GHz) |
| `--bssid`    | filter results to an access point       |
| `--ssid`     | filter results to a network name        |

Next: [Pipeline stages](stages.md).