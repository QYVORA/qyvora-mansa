# Testing and validation

Run the Go suite and static checks from the repository root:

```sh
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Simulation fixtures exercise CLI sessions, structured events, capture writing,
BLE scanning, and persisted observations without requiring radio hardware.
Parser tests cover truncated and malformed WLAN, PCAP/PCAPNG, BLE advertising,
HCI report, and GATT inputs. Linux adapter operations use injected command,
sysfs, and socket fixtures where practical.

Fuzz parser packages with `go test -fuzz=Fuzz -fuzztime=30s` from the relevant
package. Benchmarks are listed in [performance.md](performance.md).

## Operation framework coverage

`internal/operation`, `internal/lab`, `internal/active`, and
`internal/exploitation` are covered without radio hardware:

- every executor gate is exercised independently — unauthorized target,
  missing required parameter, class mismatch, out-of-scope target type,
  unavailable hardware, unwritable interface, and `--sim` against a module with
  no simulation path
- each terminal path emits its event, including the refused path
- a module exceeding the executor's hard frame limit is recorded as failed
- the harness bounds frames per run, listen windows, and retained frames; a
  refused oversized batch never reaches the transmit path
- a run returns when its context ends rather than waiting out its window
- exploitation refuses a broadcast station, a count above its ceiling, an
  unparseable station, an oversized SSID, and a missing laboratory
  acknowledgement, and asserts that no frames were transmitted in each case
- exploitation metadata is asserted to declare prerequisites, limitations,
  evidence, a vulnerability class, an affected component, cleanup, and
  non-reversibility
- simulation runs are asserted to state that nothing reached the air
- validation modules are asserted to produce evidence for the devices and
  characteristics they review, with the confidence their evidence supports
- the capability contract is asserted to contain every registered module, so
  the published contract cannot drift from the registry

Physical Linux WLAN and Bluetooth adapter validation has not been completed
in this environment. Simulation tests do not establish chipset/driver support,
regulatory behavior, packet throughput, or RF correctness. In particular, no
test here demonstrates that a transmitted frame reached the air or that any
device responded to one.
