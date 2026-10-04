//go:build linux

package transport

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestVisitRingBlock(t *testing.T) {
	block := make([]byte, 256)
	hdr := &unix.TpacketHdrV1{Num_pkts: 1, Offset_to_first_pkt: 48}
	packet := block[48:]
	binary.LittleEndian.PutUint32(packet[4:8], 123)
	binary.LittleEndian.PutUint32(packet[8:12], 456)
	binary.LittleEndian.PutUint32(packet[12:16], 4)
	binary.LittleEndian.PutUint32(packet[16:20], 4)
	binary.LittleEndian.PutUint16(packet[24:26], 48)
	copy(block[96:100], []byte{1, 2, 3, 4})
	var got int
	err := visitRingBlock(block, hdr, func(at time.Time, frame []byte) error {
		got++
		if at.Unix() != 123 || at.Nanosecond() != 456 || len(frame) != 4 || frame[3] != 4 {
			t.Fatalf("unexpected packet: at=%v frame=%v", at, frame)
		}
		return nil
	})
	if err != nil || got != 1 {
		t.Fatalf("visitRingBlock() got count=%d err=%v", got, err)
	}
}

func TestVisitRingBlockRejectsOutOfBoundsFrame(t *testing.T) {
	block := make([]byte, 128)
	hdr := &unix.TpacketHdrV1{Num_pkts: 1, Offset_to_first_pkt: 48}
	packet := block[48:]
	binary.LittleEndian.PutUint32(packet[12:16], 100)
	binary.LittleEndian.PutUint16(packet[24:26], 48)
	if err := visitRingBlock(block, hdr, func(time.Time, []byte) error { t.Fatal("unexpected callback"); return nil }); err == nil {
		t.Fatal("expected out-of-bounds frame error")
	}
}
