package wireless

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseManagementFrame(t *testing.T) {
	packet := make([]byte, 24)
	binary.LittleEndian.PutUint16(packet, uint16(8<<4)) // beacon
	copy(packet[4:10], []byte{0, 1, 2, 3, 4, 5})
	copy(packet[10:16], []byte{6, 7, 8, 9, 10, 11})
	binary.LittleEndian.PutUint16(packet[22:24], 0x1235)

	got, err := ParseFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != FrameManagement || got.Subtype != 8 || got.HeaderLength != 24 {
		t.Fatalf("unexpected parsed frame: %+v", got)
	}
	if got.Sequence != 0x123 || got.Fragment != 5 || !got.HasAddress3 {
		t.Fatalf("sequence/address fields not parsed: %+v", got)
	}
}

func TestParseControlAndFourAddressQoSData(t *testing.T) {
	ack := make([]byte, 10)
	binary.LittleEndian.PutUint16(ack, uint16(13<<4|1<<2))
	if got, err := ParseFrame(ack); err != nil || got.Type != FrameControl || got.HeaderLength != 10 || !got.HasAddress1 || got.HasAddress2 {
		t.Fatalf("ACK parse = %+v, %v", got, err)
	}

	packet := make([]byte, 36)
	binary.LittleEndian.PutUint16(packet, uint16(8<<4|2<<2|1<<8|1<<9|1<<15))
	got, err := ParseFrame(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != FrameData || !got.ToDS || !got.FromDS || !got.HasAddress4 || got.HeaderLength != 36 {
		t.Fatalf("unexpected WDS QoS frame: %+v", got)
	}
}

func TestParseFrameRejectsMalformedInput(t *testing.T) {
	for _, packet := range [][]byte{{}, {0}, make([]byte, 23), {3, 0}} {
		if _, err := ParseFrame(packet); err == nil {
			t.Errorf("ParseFrame(%v) succeeded", packet)
		}
	}
	if _, err := ParseFrame([]byte{3, 0}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version error = %v", err)
	}
	// WDS QoS data needs 24-byte base + address 4 + QoS control.
	short := make([]byte, 31)
	binary.LittleEndian.PutUint16(short, uint16(8<<4|2<<2|1<<8|1<<9))
	if _, err := ParseFrame(short); !errors.Is(err, ErrFrameTooShort) {
		t.Fatalf("truncated WDS frame error = %v", err)
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(make([]byte, 0))
	beacon := make([]byte, 24)
	binary.LittleEndian.PutUint16(beacon, uint16(8<<4))
	f.Add(beacon)
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = ParseFrame(packet)
	})
}

func BenchmarkParseFrame(b *testing.B) {
	packet := make([]byte, 24)
	binary.LittleEndian.PutUint16(packet, uint16(8<<4))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ParseFrame(packet); err != nil {
			b.Fatal(err)
		}
	}
}
