# CLI Reference

`mansa` follows the shared QYVORA tier grammar:

```
mansa <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

| Command | Purpose |
|---------|---------|
| `mansa recon analyze` | Analyze the latest session for security findings |
| `mansa recon assess` | Run the full wireless assessment pipeline |
| `mansa recon bluetooth` | Bluetooth and BLE analysis |
| `mansa recon capabilities` | List the machine-readable capability contract |
| `mansa recon capture` | Capture live wireless frames or analyze offline capture files |
| `mansa recon completion` | Generate shell completion scripts |
| `mansa recon credentials` | Assess captured WPA/WPA2 handshake material against candidate passphrases |
| `mansa recon discover` | Discover wireless interfaces and capabilities |
| `mansa recon enumerate` | Enumerate access-point inventory with filtering |
| `mansa recon events` | Show stored events for a session |
| `mansa recon evidence` | Show evidence collected in a session |
| `mansa recon exploit` | Run exploitation modules: drive an authorized laboratory target toward a known outcome |
| `mansa recon findings` | Show findings from a session |
| `mansa recon help` | Help about any command |
| `mansa recon observe` | Observe wireless clients/stations and observations |
| `mansa recon report` | Render a formatting report for a session |
| `mansa recon scan` | Scan for wireless networks and access points |
| `mansa recon session` | Inspect saved sessions |
| `mansa recon target` | Manage assessment targets |
| `mansa recon test` | Run active-test modules: transmit a bounded, declared frame set at an authorized target |
| `mansa recon tui` | start the interactive terminal application |
| `mansa recon updates` | Check for and install Mansa updates |
| `mansa recon validate` | Run validation modules: confirm or refute an observed condition from collected data |
| `mansa recon version` | Print version information |

## exploit

| Command | Purpose |
|---------|---------|
| `mansa exploit list` | List the modules in this class |
| `mansa exploit wifi.beacon.spoof.lab` | Beacon Impersonation (high risk) |
| `mansa exploit wifi.management.disruption.lab` | Management Frame Disruption (high risk) |

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `mansa analyze` | Analyze the latest session for security findings |
| `mansa assess` | Run the full wireless assessment pipeline |
| `mansa bluetooth` | Bluetooth and BLE analysis |
| `mansa capture` | Capture live wireless frames or analyze offline capture files |
| `mansa credentials` | Assess captured WPA/WPA2 handshake material against candidate passphrases |
| `mansa discover` | Discover wireless interfaces and capabilities |
| `mansa enumerate` | Enumerate access-point inventory with filtering |
| `mansa events` | Show stored events for a session |
| `mansa evidence` | Show evidence collected in a session |
| `mansa findings` | Show findings from a session |
| `mansa observe` | Observe wireless clients/stations and observations |
| `mansa scan` | Scan for wireless networks and access points |
| `mansa session` | Inspect saved sessions |
| `mansa target` | Manage assessment targets |
| `mansa test` | Run active-test modules: transmit a bounded, declared frame set at an authorized target |
| `mansa tui` | start the interactive terminal application |
| `mansa validate` | Run validation modules: confirm or refute an observed condition from collected data |

