# Capture and parser performance

Mansa keeps capture ingestion bounded and ordered. On Linux it attempts a
TPACKET_V3 memory-mapped ring and falls back to the passive AF_PACKET receive
path if ring setup is unavailable. Both feed a bounded Go queue with packet
copying at the ownership boundary and backpressure when consumers fall behind.
The current capture callback still writes PCAP and updates topology on the
consumer path; this is not a multi-worker parsing pipeline.

Benchmarks are reproducible with:

```sh
go test ./internal/wireless -run '^$' -bench . -benchmem
go test ./internal/bluetooth -run '^$' -bench . -benchmem
```

Recorded linux/amd64 fixture results (Intel Core i7-9850H): frame parsing
15.67 ns/op, 0 B/op, 0 allocs/op; PCAP AP inventory 26.7 µs/op, 70.7 KB/op,
12 allocs/op; BLE advertisement parse 1.44 µs/op, 376 B/op, 7 allocs/op; HCI
legacy report parse 1.35 µs/op, 224 B/op, 6 allocs/op. These are fixture
microbenchmarks, not line-rate hardware results. Live packet rates, drops,
queue latency, CPU, and memory have not been measured on a physical adapter.

The capture inventory bounds APs, stations, authentication records, probe
names, packet sizes, and WEP IV tracking. When the IV tracking cap is reached,
the summary marks counts as truncated. Do not interpret capped observations as
complete capture statistics.
