package wireless

import (
	"bytes"
	"testing"
	"time"
)

func TestPCAPWriterRoundTrip(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPCAPWriter(&output, 105)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 12, 30, 15, 987654000, time.UTC)
	packet := make([]byte, 24)
	if err := writer.WritePacket(at, packet); err != nil {
		t.Fatal(err)
	}
	got := 0
	summary, err := ReadPCAP(&output, func(record PacketRecord) error {
		got++
		if !record.Timestamp.Equal(at) {
			t.Errorf("timestamp = %s, want %s", record.Timestamp, at)
		}
		if !bytes.Equal(record.Data, packet) {
			t.Errorf("data = %v, want %v", record.Data, packet)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.LinkType != 105 {
		t.Errorf("link type = %d, want 105", summary.LinkType)
	}
	if got != 1 {
		t.Fatalf("records = %d, want 1", got)
	}
}

func TestPCAPWriterRejectsOversizedPacket(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPCAPWriter(&output, 105)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WritePacket(time.Now(), make([]byte, defaultPCAPSnapLen+1)); err == nil {
		t.Fatal("oversized packet was accepted")
	}
}
