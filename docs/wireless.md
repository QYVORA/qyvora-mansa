# WLAN capture and analysis status

Mansa parses raw 802.11 and radiotap frames from offline PCAP/PCAPNG files and
passively captures on Linux monitor interfaces. It builds AP/client topology,
decodes selected beacon/probe information elements, and preserves capture file
hashes in sessions. Live Linux capture uses TPACKET_V3 where available and a
bounded ordered queue. Channel inventory, fixed-channel capture, hopping,
restoration, and temporary monitor-interface leases use the radio-reported
`iw phy` inventory and Linux controls.

Offline authentication observations include unprotected WPA/WPA2 EAPOL-Key
M1–M4 classification, observed M1/M2 and M3/M4 message-set correlation by
station and replay counter, and PMKID KDE hashes. This correlation is not MIC
verification or proof of a usable credential. When an AP advertises WEP, analysis
also counts protected legacy-IV frames and bounded unique/duplicate IVs. The IV
tracker caps at 1,048,576 entries and indicates truncation. These are passive
observations, not credential verification or key recovery.

The parser records WPA3/SAE, enterprise AKM, cipher, and PMF advertisement
metadata when present in RSN elements. Protocol-specific authentication
verification, complete handshake correlation, active injection/testing,
exploitation, multi-radio orchestration, and physical adapter validation are
not implemented. Hardware and regulatory support is platform/driver dependent;
see [hardware.md](hardware.md) and [authorization.md](authorization.md).
