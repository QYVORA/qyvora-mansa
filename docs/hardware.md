# Hardware capability reporting

`mansa capabilities` lists Mansa's static, machine-readable command contract.
Use `mansa capabilities --hardware` for the runtime provider and host view:

```sh
mansa capabilities --hardware -o json
mansa capabilities --hardware --sim -o json
```

The report keeps implementation and hardware state separate. For example,
interface discovery can be implemented while monitor-mode availability remains
unknown because Mansa has not queried the radio's supported interface modes.
The Linux provider currently detects whether `iw` is installed and lists the
interfaces returned by `iw dev`. It checks each reported interface's kernel
link type for raw 802.11 or radiotap framing. This only identifies interfaces
already configured for monitor capture; it does not switch modes or channels.
Raw capture uses a passive Linux `AF_PACKET` socket and requires `CAP_NET_RAW`
or equivalent privileges. Creating a temporary monitor interface requires
`iw`, `CAP_NET_ADMIN` or equivalent privileges, and driver support. Mansa
creates and removes only the named temporary interface; it does not switch the
parent interface mode. Linux HCI adapter metadata is also read from
`/sys/class/bluetooth` without changing adapter state. Frame injection and live GATT enumeration are not implemented. BLE passive
scan requires an already powered HCI adapter and `CAP_NET_RAW`; Mansa does not
power the adapter or connect to discovered devices.

The `--sim` report describes deterministic fixture support and marks physical
hardware as not applicable. It does not imply a real radio operation ran.

To save a bounded, authorized capture from a preconfigured interface:

```sh
mansa capture live --interface mon0 --duration 30s --out lab.pcap --authorized
mansa capture live --interface wlan0 --monitor-interface mansa-mon0 --duration 30s --authorized
mansa capture live --interface mon0 --channel 6 --duration 30s --authorized
mansa capture live --interface mon0 --hop 1,6,11 --dwell 400ms --duration 30s --authorized
mansa capture live --sim --out simulated.pcap -o json
```

The command refuses to overwrite an existing path and creates the file with
owner-only permissions. It stops on the duration limit or context cancellation,
then analyzes the saved frames through Mansa's session pipeline and records a
SHA-256 evidence reference. Offline analysis also records unprotected EAPOL-Key
message types and PMKID KDE hashes when present; it does not claim credentials
can be recovered. Fixed-channel and hopping modes use channels
reported for that radio, and restore the channel observed before capture on exit.
During capture, JSONL and the shared TUI receive one discovery event for each
new AP and client as frames arrive. The final PCAP analysis still creates the
complete saved topology after capture stops.
Simulation writes deterministic beacon and probe-request fixtures immediately,
then exercises the same PCAP import, session, and analysis path without a
wireless adapter or authorization grant.

The current provider uses plain `AF_PACKET` receive calls. Linux documents
`PACKET_MMAP` as the higher-throughput ring-buffer path; Mansa has not
implemented that optimization yet. See the [Linux kernel packet mmap documentation](https://docs.kernel.org/networking/packet_mmap.html).

Status meanings:

- `available`: the provider or observed device is present for this capability.
- `unavailable`: a required provider/device is absent or the operation is not
  supported by the selected provider.
- `unknown`: the current implementation has not safely checked the hardware
  condition.
- `not_implemented`: Mansa does not implement the capability yet.
- `simulated`: the result comes from a simulation fixture.
- `not_applicable`: a physical hardware status does not apply to simulation.

Do not treat an `unknown` hardware state as support. A future native Linux
radio adapter should replace unknown states with results from the kernel's
wireless interfaces, without changing the static capability contract.
