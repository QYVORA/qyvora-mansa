# Data collection

Mansa captures structured wireless data at each collection stage and
persists it in a session file. This page describes what is collected,
how it is stored, and how to inspect it.

## Discover

Reports wireless interfaces visible to the transport backend.

| Field       | Meaning                              |
|-------------|--------------------------------------|
| `name`      | Interface name (`wlan0`, etc.)       |
| `state`     | `up` or `down`                       |
| `mode`      | `managed`, `monitor`, etc.           |
| `supported` | Bands the interface reports support for |

In simulation mode, two fixed interfaces are returned.

## Enumerate

Returns a table of discovered access points.

| Field          | Meaning                           |
|----------------|-----------------------------------|
| `bssid`        | Radio MAC (e.g. `02:00:00:00:00:01`) |
| `ssid`         | Network name (empty = hidden)     |
| `channel`      | Numeric channel                   |
| `frequency`    | Center frequency in MHz           |
| `band`         | `2.4GHz`, `5GHz`, `6GHz`         |
| `signal`       | RSSI in dBm                       |
| `security`     | Advertised security state         |
| `security.protocols` | Advertised protocol names  |
| `security.cipher`    | Active cipher suite         |
| `security.wps`       | WPS flag                   |
| `vendor`       | OUI-based vendor lookup           |
| `first_seen`   | Timestamp of first discovery      |
| `source`       | Backend name (`simulation` or `linux-iw`) |

## Observe

Captures wireless client (station) observations.

| Field    | Meaning                     |
|----------|-----------------------------|
| `mac`    | Station MAC                 |
| `ap_bssid`| Associated access point MAC |
| `signal` | RSSI in dBm                |

## Sessions

All collected data lives inside a **session**:

```
sessions/
  sess-97c8ac1e9ae6fa1a.session.json
  sess-8a10d166e28579e5.session.json
```

A session includes every collected artifact, all findings, all evidence,
risk scores, and the ordered trace of stages that were executed.

Use `mansa session` (one-shot) or the console `session` command to list
available sessions. Load the latest with `mansa analyze` (no
`--session` flag required), or pass an explicit session ID:

```sh
mansa analyze --session sess-97c8ac1e9ae6fa1a
```

## Inspecting data programmatically

The session JSON is fully stable and documented by the model structs in
`pkg/models/`. Every field maps 1:1 to a Go type. The output is
explicitly designed to be parsable by downstream tools without any
Mansa-specific logic.

Next: [Analysis rules](analysis-rules.md).