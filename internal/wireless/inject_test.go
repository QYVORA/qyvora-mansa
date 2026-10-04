package wireless

import (
	"encoding/binary"
	"testing"
	"time"
)

// fixedTime keeps frame parsing deterministic: the clock is not part of what
// these tests assert.
func fixedTime() time.Time { return time.Unix(1, 0).UTC() }

func TestParseMACAddressAcceptsCanonicalForms(t *testing.T) {
	tests := map[string]string{
		"aa:bb:cc:dd:ee:ff": "aa:bb:cc:dd:ee:ff",
		"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
		"02:00:00:00:00:01": "02:00:00:00:00:01",
	}
	for input, want := range tests {
		got, err := ParseMACAddress(input)
		if err != nil {
			t.Fatalf("ParseMACAddress(%q) = %v", input, err)
		}
		if got.String() != want {
			t.Fatalf("ParseMACAddress(%q) = %s, want %s", input, got, want)
		}
	}
}

func TestParseMACAddressRejectsMalformedInput(t *testing.T) {
	tests := map[string]string{
		"wrong length":        "aa:bb:cc:dd:ee",
		"missing separator":   "aabb:cc:dd:ee:ff:00",
		"non-hex digit":       "aa:bb:cc:dd:ee:zz",
		"all zero":            "00:00:00:00:00:00",
		"broadcast as source": "ff:ff:ff:ff:ff:ff",
		"empty":               "",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMACAddress(input); err == nil {
				t.Fatalf("ParseMACAddress(%q) must be refused", input)
			}
		})
	}
}

func TestAddressClassification(t *testing.T) {
	if !BroadcastAddress.IsBroadcast() || BroadcastAddress.IsZero() {
		t.Fatal("the broadcast address must classify as broadcast and not as zero")
	}
	if (MACAddress{}).IsBroadcast() || !(MACAddress{}).IsZero() {
		t.Fatal("the all-zero address must classify as zero and not as broadcast")
	}
}

func TestBuildDisassociationRefusesBroadcastReceiver(t *testing.T) {
	source := MACAddress{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	bssid := MACAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for _, subtype := range []uint8{SubtypeDisassociation, SubtypeDeauthentication} {
		if _, err := BuildDisassociation(subtype, BroadcastAddress, source, bssid, ReasonDeauthenticated, 1); err == nil {
			t.Fatalf("subtype %d: a broadcast receiver must be refused", subtype)
		}
		frame, err := BuildDisassociation(subtype, bssid, source, bssid, ReasonDeauthenticated, 1)
		if err != nil {
			t.Fatalf("subtype %d: %v", subtype, err)
		}
		if len(frame) < 24 {
			t.Fatalf("subtype %d: frame is %d bytes, shorter than a MAC header", subtype, len(frame))
		}
		parsed, parseErr := ParseCapturePacket(105, fixedTime(), frame)
		if parseErr != nil {
			t.Fatalf("subtype %d: %v", subtype, parseErr)
		}
		if parsed.Frame.Subtype != subtype || parsed.Frame.Type != FrameManagement {
			t.Fatalf("subtype %d: parsed type/subtype = %d/%d", subtype, parsed.Frame.Type, parsed.Frame.Subtype)
		}
		if parsed.Frame.Address1 != bssid || parsed.Frame.Address2 != source || parsed.Frame.Address3 != bssid {
			t.Fatal("the addressed fields do not match what was requested")
		}
	}
}

func TestBuildBeaconAdvertisesTheRequestedSSID(t *testing.T) {
	source := MACAddress{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	frame, err := BuildBeacon(source, "authorized-net", 0x0011, 7)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCapturePacket(105, fixedTime(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Frame.Subtype != SubtypeBeacon || parsed.Frame.Address1 != BroadcastAddress {
		t.Fatal("a beacon must be broadcast from the advertising interface")
	}
	elements, err := ParseBeaconProbeResponse(parsed.Data)
	if err != nil {
		t.Fatal(err)
	}
	if elements.SSID != "authorized-net" {
		t.Fatalf("SSID = %q, want the requested one", elements.SSID)
	}
	// A beacon body is timestamp, beacon interval, capability, then the SSID.
	if got := binary.LittleEndian.Uint16(parsed.Data[parsed.Frame.HeaderLength+8 : parsed.Frame.HeaderLength+10]); got != 100 {
		t.Fatalf("beacon interval = %d, want the fixed value the builder uses", got)
	}
	if got := binary.LittleEndian.Uint16(parsed.Data[parsed.Frame.HeaderLength+10 : parsed.Frame.HeaderLength+12]); got != 0x0011 {
		t.Fatalf("capability field = %#04x, want the requested value reported verbatim", got)
	}
}

func TestBuildBeaconRefusesAnOversizedSSID(t *testing.T) {
	source := MACAddress{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	long := make([]byte, 33)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := BuildBeacon(source, string(long), 0, 1); err == nil {
		t.Fatal("an SSID longer than 32 bytes must be refused")
	}
}

func TestSequenceNumberWrapsAtTwelveBits(t *testing.T) {
	if got := SequenceNumber(0x0fff); got != 0 {
		t.Fatalf("SequenceNumber(0x0fff) = %#x, want it to wrap to 0", got)
	}
	if got := SequenceNumber(41); got != 42 {
		t.Fatalf("SequenceNumber(41) = %d, want 42", got)
	}
}

func TestRadiotapHeaderIsMinimalAndFlagged(t *testing.T) {
	header := RadiotapHeader()
	if len(header) < 8 {
		t.Fatalf("radiotap header is %d bytes, too short to hold its own fields", len(header))
	}
	version := header[0]
	if version != 0 {
		t.Fatalf("radiotap version = %d, want 0", version)
	}
	if got := binary.LittleEndian.Uint16(header[2:4]); got != uint16(len(header)) {
		t.Fatalf("header length field = %d, want the header's own size %d", got, len(header))
	}
	if got := binary.LittleEndian.Uint32(header[4:8]); got != 0 {
		t.Fatalf("present bitmap = %#x, want no optional fields", got)
	}
}
