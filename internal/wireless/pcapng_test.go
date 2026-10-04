package wireless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestReadPCAPNGEnhancedPacket(t *testing.T) {
	var bssid [6]byte
	copy(bssid[:], []byte{0x02, 0, 0, 0, 0, 1})
	frame := makeBeaconFrame(bssid, []byte("ng-ap"), 11, false)
	data := makePCAPNG(frame)
	var called bool
	summary, err := ReadCapture(bytes.NewReader(data), func(record PacketRecord) error {
		called = true
		if record.FrameError != nil || record.Frame.Type != FrameManagement || record.Timestamp.Unix() != 1 || record.Timestamp.Nanosecond() != 500_000_000 {
			t.Errorf("record = %+v", record)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called || summary.Interfaces != 1 || summary.Packets != 1 || summary.LinkType != linkTypeIEEE80211 {
		t.Fatalf("summary = %+v, callback = %v", summary, called)
	}
	inventory, err := ReadPCAPInventory(bytes.NewReader(data))
	if err != nil || len(inventory.AccessPoints) != 1 || inventory.AccessPoints[0].SSID != "ng-ap" {
		t.Fatalf("PCAPNG inventory = %+v, err=%v", inventory, err)
	}
}

func TestReadPCAPNGRejectsMalformedBlock(t *testing.T) {
	data := makePCAPNG(nil)
	data[len(data)-1] ^= 0xff // break final block length trailer
	if _, err := ReadCapture(bytes.NewReader(data), nil); !errors.Is(err, ErrMalformedPCAP) {
		t.Fatalf("malformed block error = %v", err)
	}
}

func makePCAPNG(frame []byte) []byte {
	var out bytes.Buffer
	order := binary.LittleEndian
	// Section Header Block
	var section [28]byte
	copy(section[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a})
	order.PutUint32(section[4:8], 28)
	copy(section[8:12], []byte{0x4d, 0x3c, 0x2b, 0x1a})
	order.PutUint16(section[12:14], 1)
	order.PutUint16(section[14:16], 0)
	order.PutUint64(section[16:24], ^uint64(0))
	order.PutUint32(section[24:28], 28)
	out.Write(section[:])
	// Interface Description Block
	var iface [20]byte
	order.PutUint32(iface[0:4], pcapngInterface)
	order.PutUint32(iface[4:8], 20)
	order.PutUint16(iface[8:10], uint16(linkTypeIEEE80211))
	order.PutUint32(iface[12:16], 65535)
	order.PutUint32(iface[16:20], 20)
	out.Write(iface[:])
	// Enhanced Packet Block; default interface timestamp resolution is µs.
	padded := int(pad4(uint32(len(frame))))
	total := 32 + padded
	block := make([]byte, total)
	order.PutUint32(block[0:4], pcapngEnhancedPacket)
	order.PutUint32(block[4:8], uint32(total))
	order.PutUint32(block[12:16], 0)
	order.PutUint32(block[16:20], 1_500_000)
	order.PutUint32(block[20:24], uint32(len(frame)))
	order.PutUint32(block[24:28], uint32(len(frame)))
	copy(block[28:], frame)
	order.PutUint32(block[total-4:], uint32(total))
	out.Write(block)
	return out.Bytes()
}
