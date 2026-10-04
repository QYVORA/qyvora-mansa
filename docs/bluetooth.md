# Bluetooth and BLE status

Mansa currently provides a platform independent parser for captured BLE
advertising data structures. It normalizes local names, signed TX power,
16/32/128-bit service UUIDs, and manufacturer-specific payloads. Payloads are
bounded to 1650 bytes and malformed field lengths return errors.

```sh
mansa bluetooth parse-advertisement 03030f18020af4 -o json
mansa bluetooth parse-hci-event 043e10020100000605040302010403030f18d6 -o json
mansa bluetooth parse-advertisement --sim -o json
mansa bluetooth parse-hci-event --sim -o json
```

The HCI event parser handles legacy and extended LE Advertising Report events,
including RSSI availability, controller TX power, PHY, SID, and data status.
The parser is an offline analysis primitive. On Linux, Mansa can passively scan advertisements through a raw HCI socket. It requires an already powered adapter and `CAP_NET_RAW`; it never powers the adapter or connects to discovered devices. The scan is authorization-gated, cancellable, bounded to 10 minutes, writes a session with device observations and hashes, and emits structured discovery/update events. A deterministic fixture exercises the same CLI/session flow:

```sh
mansa bluetooth scan --adapter hci0 --duration 15s --authorized -o json
mansa bluetooth scan --sim -o json
```

Mansa also accepts normalized
GATT metadata snapshots and flags writable characteristics for which the
provider reports no encryption, authentication, or authorization restriction:

```sh
mansa bluetooth analyze-gatt gatt-snapshot.json -o json
mansa bluetooth analyze-gatt --sim -o json
```

This is a cautious review signal, not proof that a remote client can write the
attribute. Linux HCI adapter metadata can be listed with
`mansa bluetooth adapters`; it is read from sysfs without powering an adapter on.
Classic Bluetooth discovery and live GATT enumeration are not implemented.

A raw HCI channel adds one read-only query beyond sysfs: `mansa validate
ble.adapter.capabilities` reads local version, BD_ADDR, the supported-command
bitmap, LE features, and the LE ACL buffer size. It issues no command that
enables scanning, changes power state, or pairs. A query that returns no data
is recorded by name rather than filled with a guess, and the run states that
the recorded capability set is incomplete.

Bluetooth validation modules review data already collected and emit nothing:
`ble.adapter.capabilities`, `ble.advertising.exposure`, and
`ble.gatt.access.control`. See [active testing](active-testing.md) for the
gates they share with the other operation classes.
`mansa capabilities --hardware` reports BLE scanning implementation separately
from adapter readiness; offline parsing or simulation does not imply an adapter
is present.

The implementation is native Go and does not copy BlueZ source. Its data
structure handling follows the [Bluetooth Core Specification Supplement, Part A](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/CSS_v14/out/en/core-supplementary-features/data-types-specification.html)
and little-endian UUID encodings.
