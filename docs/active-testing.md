# Active testing

An **active test** answers a question by transmitting a bounded, declared set
of frames at an authorized target and reporting what the interface actually
answered. It is one of three operation classes in Mansa, alongside validation
and exploitation.

| Class           | Command    | Emits frames | Changes the target's environment |
|-----------------|------------|--------------|----------------------------------|
| `validation`    | `mansa validate` | no   | no  |
| `active_test`   | `mansa test`     | yes  | yes |
| `exploitation`  | `mansa exploit`  | yes  | yes |

Validation modules review data already collected. Active tests emit traffic.
Exploitation modules drive a target toward a known outcome. All three run
through the same executor, so they share identical gating, recording, and
evidence rules.

## Gates

Every run passes these gates in order, whether it is a dry run or a real one:

1. **Module resolution.** The module must exist and declare the class the
   command runs.
2. **Required parameters.** A missing required parameter is a usage error.
3. **Target presence.** A run without a target is refused.
4. **Authorization.** A non-simulated run requires an authorized target
   ([authorization](authorization.md)).
5. **Scope.** The target's type must be one the module declares it accepts.
   A module declared for `bssid` is refused an `interface` target.
6. **Hardware.** A module declaring `RequiredHardware` is refused unless the
   provider can probe the named interface and reports it writable.
7. **Simulation honesty.** `--sim` runs only a module that declares
   `SimulationAvailable`.

Add `--dry-run` to see the plan a module would follow. Planning runs the same
gates, so a dry run cannot describe a run that would be refused.

```sh
mansa test list
mansa test wifi.management.protection.probe \
  --target aa:bb:cc:dd:ee:ff --interface wlan0 -y \
  --param station=11:22:33:44:55:66 --dry-run
```

## Bounds

Active tests are bounded in four independent ways, and each bound is enforced
separately from the module that declares it:

| Bound                | Ceiling     | Enforced by                                  |
|----------------------|-------------|----------------------------------------------|
| Frames per run       | 256         | module, `lab.TransmitAndListen`, and the executor's `HardLimit` |
| Listen window        | 30s         | module parameter validation                  |
| Run duration         | per module  | executor context timeout                     |
| Retained frames      | 4096        | `lab.Collector`                              |

A count above a module's ceiling is refused, not clamped: a silent clamp would
make a run report a different test than the one that was asked for.

## What a test may not do

- **Transmit to a broadcast destination.** `wireless.BuildDisassociation`
  refuses a broadcast receiver outright. Disruption scoped to one authorized
  station cannot be expressed as a broadcast frame.
- **Act without a named target.** A module that needs a station requires
  `--param station`; the executor refuses the run before any I/O.
- **Claim delivery.** `FramesTransmitted` is what the kernel accepted. It is
  not proof a frame reached the air, and no module reports it as such.
- **Modify adapter state.** No module changes channel, power, or monitor-mode
  configuration. Channel changes belong to the capture command, which restores
  the prior channel.

## Hardware requirements

Modules declare what they need:

- `monitor_mode` — the interface must be in monitor mode to observe frames.
- `raw_frame_transmit` — the interface must accept raw frame writes.

When the provider cannot satisfy a requirement, the run is reported as
`unavailable` with the reason. It is never reported as a success, and it is
never silently downgraded to a simulation run.

## Evidence

Each run records:

- the operator, target, target type, interface, and authorization method
- the authorization scope the human agreed to
- frames and bytes the kernel accepted
- a per-run SHA-256 over the exact constructed bytes transmitted
- the frames observed in the listen window, including malformed and truncated
  counts
- the module's findings, with confidence and evidence
- stated limitations, including what the run could not conclude
- cleanup state

Operation records are stored on the session, so `mansa findings` and
`mansa evidence` show active-test results alongside passive ones.

## Modules

| Module                            | Question it answers                                        |
|-----------------------------------|------------------------------------------------------------|
| `wifi.inject.verify`              | Does this interface transmit, and does anything answer?     |
| `wifi.management.protection.probe`| Does the AP protect management frames addressed to a station? |
| `wifi.authentication.probe`       | How does the AP answer an authentication request?           |

## Simulation

`--sim` runs the same module code against the deterministic fixture provider.
The run constructs the same frames and records the same evidence, and reports
that nothing reached the air. A simulated run never reports a successful
exchange.

```sh
mansa test wifi.inject.verify --sim
```

Simulation exercises the code path and the reporting; it demonstrates nothing
about any real network.

## See also

- [Exploitation](exploitation.md) — the higher-risk class
- [Authorization](authorization.md) — how scope is granted
- [Events](events.md) — lifecycle events emitted per run