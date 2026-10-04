package wireless

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

func TestReadPCAPStreams80211Frames(t *testing.T) {
	frame := make([]byte, 24)
	binary.LittleEndian.PutUint16(frame, uint16(8<<4))
	data := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{frame, {0, 0}})
	var seen int
	summary, err := ReadPCAP(bytes.NewReader(data), func(record PacketRecord) error {
		seen++
		if seen == 1 && (record.Frame.Type != FrameManagement || record.FrameError != nil || record.Timestamp.Unix() != 10) {
			t.Errorf("first record = %+v", record)
		}
		if seen == 2 && !errors.Is(record.FrameError, ErrFrameTooShort) {
			t.Errorf("second frame error = %v", record.FrameError)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 2 || summary.Packets != 2 || summary.Malformed != 1 || summary.LinkType != linkTypeIEEE80211 {
		t.Fatalf("summary = %+v, callbacks = %d", summary, seen)
	}
	if !summary.FirstPacketAt.Equal(time.Unix(10, 250_000_000).UTC()) {
		t.Errorf("first timestamp = %s", summary.FirstPacketAt)
	}
}

func TestReadPCAPRadiotapAndNanoBigEndian(t *testing.T) {
	frame := make([]byte, 24)
	binary.LittleEndian.PutUint16(frame, uint16(8<<4))
	radio := make([]byte, 8+len(frame))
	binary.LittleEndian.PutUint16(radio[2:4], 8)
	copy(radio[8:], frame)
	data := makeClassicPCAP(binary.BigEndian, []byte{0xa1, 0xb2, 0x3c, 0x4d}, linkTypeRadiotap, true, [][]byte{radio})
	got, err := ReadPCAP(bytes.NewReader(data), func(record PacketRecord) error {
		if len(record.Data) != 24 || record.FrameError != nil {
			t.Errorf("radiotap record = %+v", record)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Packets != 1 || got.LastPacketAt.Nanosecond() != 250_000_000 {
		t.Fatalf("summary = %+v", got)
	}
}

func TestReadPCAPRejectsMalformedFiles(t *testing.T) {
	valid := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, nil)
	if _, err := ReadPCAP(bytes.NewReader(valid[:12]), nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated global header error = %v", err)
	}
	truncatedRecord := append(append([]byte(nil), valid...), make([]byte, 8)...)
	if _, err := ReadPCAP(bytes.NewReader(truncatedRecord), nil); !errors.Is(err, ErrMalformedPCAP) {
		t.Fatalf("truncated record error = %v", err)
	}
	unsupported := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 1, false, nil)
	if _, err := ReadPCAP(bytes.NewReader(unsupported), nil); !errors.Is(err, ErrUnsupportedLink) {
		t.Fatalf("unsupported link error = %v", err)
	}
}

func TestReadPCAPCallbackError(t *testing.T) {
	want := errors.New("stop")
	frame := make([]byte, 24)
	data := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{frame})
	if _, err := ReadPCAP(bytes.NewReader(data), func(PacketRecord) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback error = %v", err)
	}
}

func TestReadPCAPAccessPoints(t *testing.T) {
	var bssid [6]byte
	copy(bssid[:], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	hidden := makeBeaconFrame(bssid, nil, 6, false)
	visible := makeBeaconFrame(bssid, []byte("office"), 6, true)
	visible = append(visible, 221, 4, 0x00, 0x50, 0xf2, 4) // WPS advertisement
	data := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{hidden, visible})
	aps, summary, err := ReadPCAPAccessPoints(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(aps) != 1 || summary.Packets != 2 || aps[0].BSSID != "00:11:22:33:44:55" {
		t.Fatalf("APs=%+v summary=%+v", aps, summary)
	}
	if aps[0].SSID != "office" || aps[0].Hidden || aps[0].Channel != 6 || aps[0].Frequency != 2437 || aps[0].Band != "2.4GHz" {
		t.Fatalf("AP observation = %+v", aps[0])
	}
	if aps[0].Security.Auth != "WEP" || aps[0].Security.Cipher != "WEP" {
		t.Fatalf("privacy bit security = %+v", aps[0].Security)
	}
	if !aps[0].Security.WPS {
		t.Fatalf("WPS advertisement missing from AP security metadata: %+v", aps[0].Security)
	}
	if !containsString(aps[0].CapabilityFlags, "ESS") || !containsString(aps[0].CapabilityFlags, "Short-Preamble") {
		t.Fatalf("capability flags missing from AP metadata: %v", aps[0].CapabilityFlags)
	}
	if len(aps[0].SupportedRatesMbps) != 3 || aps[0].SupportedRatesMbps[2] != 6 || len(aps[0].BasicRatesMbps) != 3 {
		t.Fatalf("advertised rates = supported %v basic %v", aps[0].SupportedRatesMbps, aps[0].BasicRatesMbps)
	}
}

func TestReadPCAPAccessPointsContextCancellation(t *testing.T) {
	frame := make([]byte, 24)
	data := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{frame})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := ReadPCAPAccessPointsContext(ctx, bytes.NewReader(data))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestReadPCAPInventoryBuildsClientTopology(t *testing.T) {
	var bssid, station [6]byte
	copy(bssid[:], []byte{0x02, 0, 0, 0, 0, 1})
	copy(station[:], []byte{0x02, 0, 0, 0, 0, 2})
	beacon := makeBeaconFrame(bssid, []byte("lab"), 1, false)
	probe := make([]byte, 24)
	binary.LittleEndian.PutUint16(probe, uint16(4<<4))
	copy(probe[10:16], station[:])
	probe = append(probe, 0, 6, 'o', 'f', 'f', 'i', 'c', 'e')
	association := make([]byte, 24)
	binary.LittleEndian.PutUint16(association, uint16(0<<4))
	copy(association[4:10], bssid[:])
	copy(association[10:16], station[:])
	response := make([]byte, 30)
	binary.LittleEndian.PutUint16(response, uint16(1<<4))
	copy(response[4:10], station[:])
	copy(response[10:16], bssid[:])
	binary.LittleEndian.PutUint16(response[26:28], 0) // success status
	data := make([]byte, 24)
	binary.LittleEndian.PutUint16(data, uint16(2<<2|1<<9)) // FromDS data
	copy(data[4:10], station[:])
	copy(data[10:16], bssid[:])

	pcap := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{beacon, probe, association, response, data})
	inventory, err := ReadPCAPInventory(bytes.NewReader(pcap))
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.AccessPoints) != 1 || len(inventory.Stations) != 1 {
		t.Fatalf("inventory = %+v", inventory)
	}
	got := inventory.Stations[0]
	if got.MAC != "02:00:00:00:00:02" || got.APBSSID != "02:00:00:00:00:01" || !got.Associated {
		t.Fatalf("station relationship = %+v", got)
	}
	if len(got.ProbedSSIDs) != 1 || got.ProbedSSIDs[0] != "office" {
		t.Fatalf("probed SSIDs = %v", got.ProbedSSIDs)
	}
}

func TestReadPCAPInventoryReportsWEPIVReuseConditions(t *testing.T) {
	var bssid, station [6]byte
	copy(bssid[:], []byte{0x02, 0, 0, 0, 0, 1})
	copy(station[:], []byte{0x02, 0, 0, 0, 0, 2})
	beacon := makeBeaconFrame(bssid, []byte("legacy"), 6, true)
	protected := make([]byte, 28)
	binary.LittleEndian.PutUint16(protected, uint16(2<<2|1<<9|1<<14)) // protected FromDS data
	copy(protected[4:10], station[:])
	copy(protected[10:16], bssid[:])
	copy(protected[24:27], []byte{1, 2, 3})
	protected[27] = 0x00 // WEP key header without ExtIV
	pcap := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{beacon, protected, protected})
	inventory, err := ReadPCAPInventory(bytes.NewReader(pcap))
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Summary.WEPEncryptedFrames != 2 || inventory.Summary.WEPUniqueIVs != 1 || inventory.Summary.WEPDuplicateIVs != 1 {
		t.Fatalf("WEP summary = %+v", inventory.Summary)
	}
	if len(inventory.Authentication) != 1 || inventory.Authentication[0].Kind != "wep-capture-conditions" || inventory.Authentication[0].WEPDuplicateIVs != 1 {
		t.Fatalf("WEP observations = %+v", inventory.Authentication)
	}
}

func BenchmarkReadPCAPAccessPoints(b *testing.B) {
	var bssid [6]byte
	copy(bssid[:], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 1})
	data := makeClassicPCAP(binary.LittleEndian, []byte{0xd4, 0xc3, 0xb2, 0xa1}, linkTypeIEEE80211, false, [][]byte{makeBeaconFrame(bssid, []byte("benchmark"), 6, false)})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ReadPCAPAccessPoints(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

func makeBeaconFrame(bssid [6]byte, ssid []byte, channel byte, privacy bool) []byte {
	packet := make([]byte, 36)
	binary.LittleEndian.PutUint16(packet, uint16(8<<4))
	copy(packet[10:16], bssid[:])
	copy(packet[16:22], bssid[:])
	capabilityBits := uint16(1<<0 | 1<<5) // ESS and short preamble
	if privacy {
		capabilityBits |= 1 << 4
	}
	binary.LittleEndian.PutUint16(packet[34:36], capabilityBits)
	packet = append(packet, 0, byte(len(ssid)))
	packet = append(packet, ssid...)
	packet = append(packet, 3, 1, channel)
	packet = append(packet, 1, 2, 0x82, 0x84, 50, 1, 0x8c)
	return packet
}

func makeClassicPCAP(order binary.ByteOrder, magic []byte, link uint32, nanos bool, packets [][]byte) []byte {
	var out bytes.Buffer
	out.Write(magic)
	var global [20]byte
	order.PutUint16(global[0:2], 2)
	order.PutUint16(global[2:4], 4)
	order.PutUint32(global[12:16], 65535)
	order.PutUint32(global[16:20], link)
	out.Write(global[:])
	for _, packet := range packets {
		var header [16]byte
		order.PutUint32(header[0:4], 10)
		fraction := uint32(250_000)
		if nanos {
			fraction = 250_000_000
		}
		order.PutUint32(header[4:8], fraction)
		order.PutUint32(header[8:12], uint32(len(packet)))
		order.PutUint32(header[12:16], uint32(len(packet)))
		out.Write(header[:])
		out.Write(packet)
	}
	return out.Bytes()
}
