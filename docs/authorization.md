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
| `bluetooth-adapter` | `hci0`, ... | Passively scan LE advertisements from the named adapter |
| `capture`      | `capture.pcap` | Review an already-collected capture or snapshot |
| `simulation`   | `simulation`   | Run against a fixture; no live I/O              |

## CLI

Pass `--authorized` (or `-y`) on the one-shot command line to confirm
scope non-interactively:

```sh
mansa assess --sim                    # simulation: no authorization required
mansa assess --interface wlan0 -y     # live: confirms authorization
mansa scan -y                         # live single-stage Wi-Fi scan
mansa bluetooth scan --adapter hci0 -y # live passive BLE scan
mansa test wifi.inject.verify -y       # live bounded active test
mansa exploit wifi.beacon.spoof.lab -y # exploitation; also needs --param lab
```

Operation commands accept `--target` as a stored target id, as a literal value
such as an access point's BSSID, or as nothing at all, in which case the
interface itself is the target. All three forms end at the same gate. A
simulated run is scoped to the `simulation` target and never carries a real
target's authorization.

An operation run records the authorization scope verbatim, alongside the
operator who granted it, the method, and the interface used. The scope on the
record is the boundary a human agreed to, not the module's prerequisites.
See [active testing](active-testing.md) and [exploitation](exploitation.md).

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
  automatically authorize future runs; each live operation must pass its own
  authorization gate. Completed sessions persist the authorization record for
  audit purposes.
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