# Research and attribution

Mansa uses mature wireless projects and protocol references to check behavior,
edge cases, and hardware constraints. They are references, not runtime
dependencies or source-code donors. Implementation remains in Mansa's Go
packages. No Aircrack-ng, BlueZ, Wireshark, or Kismet source files are copied
into this repository.

## Engineering references

- [Linux cfg80211 documentation](https://docs.kernel.org/driver-api/80211/cfg80211.html)
  describes radio-reported channel and interface-combination constraints. Mansa
  enumerates channels from the active radio and does not assume a regulatory
  domain or that a virtual monitor interface can be created.
- [Linux nl80211 UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/nl80211.h)
  documents the kernel interface types and channel-control attributes. Linux
  monitor/channel control currently uses the system `iw` utility; this remains
  an explicit platform boundary, not an implementation of packet parsing or
  security analysis.
- [Aircrack-ng airodump-ng documentation](https://aircrack-ng.com/doku.php?id=airodump-ng)
  describes raw 802.11 capture, channel selection/hopping, AP/client output, and
  hidden-SSID observations. These are capability references only; Mansa does
  not wrap airodump-ng or implement its active companion behavior.
- [Wireshark capture architecture](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksCapturePackets.html)
  documents isolating privileged packet capture, and its
  [capture-file overview](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksCaptureFiles.html)
  describes PCAP/PCAPNG as exchange formats. Mansa implements its own bounded
  readers/writer and Linux capture path.
- [BlueZ Adapter D-Bus API](https://github.com/bluez/bluez/blob/master/doc/org.bluez.Adapter.rst)
  is a reference for Linux adapter discovery and scan controls. Mansa currently
  supports adapter metadata and offline advertisement/GATT analysis; live HCI
  discovery and GATT enumeration are not implemented.
- [Bluetooth Core Specification 6.2](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-62/out/en/index-en.html)
  is the protocol reference for Bluetooth/BLE fields. Mansa stores concise
  normalized metadata and does not reproduce specification text or test
  vectors.

These references were reviewed on 2026-10-03. The linked projects retain their
own licenses. Their documentation is not included in Mansa's distribution.

## Data and license review

- The root project license is MIT (`LICENSE`). `NOTICE` now lists the external
  Go modules in the compiled package graph by their upstream license files.
- The published `github.com/QYVORA/qyvora-tui` v0.7.0 module currently has no
  `LICENSE` or `COPYING` file. This is an unresolved distribution item; the
  module owner should publish licensing metadata before release.
- The bundled candidate list is a small Mansa-authored lab set. It does not
  include SecLists or another downloaded dictionary. External wordlists remain
  user-provided and are not redistributed.
- `internal/wireless/oui.go` contains a small OUI-to-vendor map. Its source and
  redistribution provenance are not recorded yet, so it must not be described
  as a complete or authoritative IEEE registry. Record the source and applicable
  terms or replace it with a documented compatible data source before release.
- No external source code, protocol specification text, generated assets, or
  wordlist entries have been copied as part of this implementation. Newly
  written parsers consume wire-format fields from publicly documented protocol
  layouts.

This is an engineering inventory, not legal advice. Re-run it when dependencies,
bundled datasets, generated assets, or copied reference material change.
