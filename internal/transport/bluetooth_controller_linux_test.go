//go:build linux

package transport

import (
	"testing"
)

func TestDecodeLEFeaturesNamesOnlyTheBitsThatAreSet(t *testing.T) {
	// LE Encryption (bit 0) and LE 2M PHY (bit 15).
	bits := make([]byte, 8)
	bits[0] = 0b0000_0001
	bits[1] = 0b1000_0000
	got := decodeLEFeatures(bits)
	want := []string{"LE Encryption", "LE 2M PHY"}
	if len(got) != len(want) {
		t.Fatalf("decodeLEFeatures = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("decodeLEFeatures = %v, want %v in bit order", got, want)
		}
	}
	if features := decodeLEFeatures(make([]byte, 8)); features != nil {
		t.Fatalf("decodeLEFeatures(all zero) = %v, want nothing reported", features)
	}
	if features := decodeLEFeatures([]byte{1, 0}); features != nil {
		t.Fatal("a short bitmap must report nothing rather than guess")
	}
}

func TestDecodeLEFeaturesIsStableInBitOrder(t *testing.T) {
	bits := make([]byte, 8)
	bits[0] = 0b0000_1001
	bits[3] = 0b0000_0110
	first := decodeLEFeatures(bits)
	for i := 0; i < 20; i++ {
		again := decodeLEFeatures(bits)
		if len(again) != len(first) {
			t.Fatal("decodeLEFeatures is not deterministic")
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("decodeLEFeatures is not deterministic: %v vs %v", first, again)
			}
		}
	}
}

func TestFormatBDAddrUsesTheSpecificationOrder(t *testing.T) {
	// A controller reports the least significant octet first; the conventional
	// written form is the reverse.
	if got := formatBDAddr([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}); got != "06:05:04:03:02:01" {
		t.Fatalf("formatBDAddr = %q, want the specification order", got)
	}
	if got := formatBDAddr([]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}); got != "00:00:00:00:00:02" {
		t.Fatalf("formatBDAddr = %q", got)
	}
	if got := formatBDAddr([]byte{1, 2, 3}); got != "" {
		t.Fatalf("formatBDAddr(short) = %q, want empty", got)
	}
}

func TestBluetoothCompanyNameFallsBackToItsNumericValue(t *testing.T) {
	if got := bluetoothCompanyName(0x05F); got != "Nordic Semiconductor" {
		t.Fatalf("bluetoothCompanyName(0x05F) = %q", got)
	}
	if got := bluetoothCompanyName(0xFFFF); got != "company 0xffff" {
		t.Fatalf("an unlisted identifier must be reported numerically, got %q", got)
	}
}

func TestSimulatedControllerInfoIsMarkedSimulated(t *testing.T) {
	info, err := (&SimBackend{}).ControllerInfo(t.Context(), "hci0")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Simulated {
		t.Fatal("the simulation provider must mark its controller info as simulated")
	}
	if info.Adapter != "hci0" {
		t.Fatalf("adapter = %q, want the requested one", info.Adapter)
	}
	if len(info.LEFeatures) == 0 || info.HCIVersionName == "" {
		t.Fatal("the fixture must carry a capability set so CI exercises the reporting path")
	}
	if _, err := (&SimBackend{}).ControllerInfo(t.Context(), ""); err == nil {
		t.Fatal("an empty adapter name must be refused")
	}
}

func TestLinuxControllerInfoRefusesAnUnparseableAdapter(t *testing.T) {
	info, err := (&LinuxBackend{}).ControllerInfo(t.Context(), "not-an-adapter")
	if err == nil {
		t.Fatal("expected an unparseable adapter name to be refused before any socket is opened")
	}
	if info.Adapter != "not-an-adapter" {
		t.Fatalf("the record should still name the adapter that was attempted, got %q", info.Adapter)
	}
}

func TestSimulatedTransmitCountsWithoutClaimingDelivery(t *testing.T) {
	backend := &SimBackend{}
	stats, err := backend.Transmit(t.Context(), "sim0", [][]byte{{1, 2, 3}, {4, 5}})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Frames != 2 || stats.Bytes != 5 {
		t.Fatalf("stats = %+v, want 2 frames / 5 bytes", stats)
	}
	linkType, err := backend.TransmitLinkType("sim0")
	if err != nil || linkType != 105 {
		t.Fatalf("TransmitLinkType = %d, %v; want the 802.11 link type", linkType, err)
	}
	capability, err := backend.ProbeTransmit("sim0")
	if err != nil {
		t.Fatal(err)
	}
	if !capability.Writable {
		t.Fatal("the simulation provider can always accept a frame")
	}
	if capability.OverAirConfirmed {
		t.Fatal("the simulation provider must never claim an over-air confirmation")
	}
}
