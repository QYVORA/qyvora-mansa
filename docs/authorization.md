# Authorization

Mansa enforces an explicit authorization gate before any live (non-sim)
wireless operation proceeds. This is the machine-enforced implementation
of Mansa's **authorized-use-only** principle.

## How authorization works

Mansa records authorization against a **target**. The target captures
the exact scope being authorized:

| Target type   | Value            | Meaning                            |
|---------------|------------------|------------------------------------|
| `interface`   | `wlan0`, ...     | Assess all networks heard via that interface |
| `ssid`        | `CoffeeShop`     | Assess only the named network      |
| `bssid`       | `AA:BB:CC:...`   | Assess only the named access point  |
| `session`     | `<session-id>`   | Re-analyze an already-collected session |

## CLI

Pass `--authorized` (or `-y`) on the one-shot command line to confirm
scope non-interactively:

```sh
mansa assess --sim                    # simulation: no authorization required
mansa assess --interface wlan0 -y     # live: confirms authorization
mansa scan -y                         # live single-stage scan
```

Without `-y` on a live run, Mansa exits with a prompt explaining the
authorization model.

## Console

Inside the interactive console, use the `authorize` command:

```
authorize           # grants current scope
authorize all       # grants all interfaces
status              # shows whether scope is authorized
```

Authorization state is reflected immediately by `status` and by the
prompt context indicator (`~auth`).

## Scope limitations

- Authorization granted in one session is **not** persisted
  automatically between restarts unless `--target` or the config file
  sets `authorized: true`.
- Simulated (`--sim`) operations are **always** authorized and are
  never gated.

## Config file

```yaml
authorized: true
```

The `authorized` default is `false`. The config key is most useful in
controlled lab environments; for interactive use, prefer `-y` or the
console `authorize` command so the human in the loop confirms scope.

Next: [Modes](modes.md).