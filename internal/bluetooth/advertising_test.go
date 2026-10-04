package bluetooth

import (
	"testing"
)

func TestParseAdvertisementReadsEveryDecodedField(t *testing.T) {
	advertisement, err := ParseAdvertisement(SimulatedAdvertisementData())
	if err != nil {
		t.Fatalf("parse simulated advertisement: %v", err)
	}
	if advertisement.Name != "Mansa Sim" {
		t.Errorf("name = %q, want %q", advertisement.Name, "Mansa Sim")
	}
	if !advertisement.CompleteName {
		t.Error("the fixture carries a complete local name, so CompleteName must be set")
	}
	if advertisement.TxPower == nil || *advertisement.TxPower != -28 {
		t.Errorf("tx power = %v, want -28", advertisement.TxPower)
	}
	if len(advertisement.ServiceUUIDs) != 1 || advertisement.ServiceUUIDs[0] != "180F-0000-1000-8000-00805F9B34FB" {
		t.Errorf("service UUIDs = %v", advertisement.ServiceUUIDs)
	}
	if len(advertisement.ManufacturerData) != 1 {
		t.Fatalf("manufacturer data = %v, want one company", advertisement.ManufacturerData)
	}
	// 0x4c 0x00 little endian is company 0x004c.
	if _, ok := advertisement.ManufacturerData[0x004c]; !ok {
		t.Errorf("manufacturer data keys = %v, want company 0x004c", advertisement.ManufacturerData)
	}
}

func TestParseAdvertisementStopsAtZeroPaddingAndSkipsUnknownTypes(t *testing.T) {
	// Flags, then an unknown type, then padding.
	payload := []byte{0x02, 0x01, 0x06, 0x03, 0x7f, 0xaa, 0xbb, 0x00, 0x00}
	advertisement, err := ParseAdvertisement(payload)
	if err != nil {
		t.Fatalf("unknown types must be skipped: %v", err)
	}
	if advertisement.Name != "" {
		t.Errorf("name = %q, want empty", advertisement.Name)
	}
}

func TestParseAdvertisementRejectsATruncatedType(t *testing.T) {
	// Claims five bytes of a complete local name but supplies two.
	payload := []byte{0x06, 0x09, 0x41, 0x42}
	if _, err := ParseAdvertisement(payload); err == nil {
		t.Fatal("expected a truncated advertising type to be refused")
	}
}

func TestParseLEAdvertisingReportsDecodesTheFixtureReport(t *testing.T) {
	observations, err := ParseLEAdvertisingReports(SimulatedLEAdvertisingReport())
	if err != nil {
		t.Fatalf("parse simulated report: %v", err)
	}
	if len(observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(observations))
	}
	got := observations[0]
	if got.Address != "05:11:2a:4f:8c:6b" {
		t.Errorf("address = %q, want %q", got.Address, "05:11:2a:4f:8c:6b")
	}
	if got.EventType != 0x03 {
		t.Errorf("event type = 0x%02x, want 0x03 (ADV_IND)", got.EventType)
	}
	if !got.RSSIAvailable || got.RSSI != -60 {
		t.Errorf("rssi = %d available=%t, want -60 available", got.RSSI, got.RSSIAvailable)
	}
	if got.Advertisement.Name != "Mansa Sim" {
		t.Errorf("advertisement name = %q, want %q", got.Advertisement.Name, "Mansa Sim")
	}
}

func TestParseLEAdvertisingReportsRefusesANonReportPacket(t *testing.T) {
	if _, err := ParseLEAdvertisingReports([]byte{0x0e, 0x01}); err == nil {
		t.Fatal("expected a Command Complete event to be refused")
	}
	if _, err := ParseLEAdvertisingReports([]byte{0x3e, 0x01}); err == nil {
		t.Fatal("expected an LE subevent that carries no reports to be refused")
	}
	if _, err := ParseLEAdvertisingReports([]byte{0x3e}); err == nil {
		t.Fatal("expected a one byte packet to be refused")
	}
}

func TestParseLEAdvertisingReportsRefusesATruncatedReport(t *testing.T) {
	// A valid header whose report claims more data than the packet holds.
	packet := []byte{hciEventLEMeta, hciSubeventLEAdvReport, 0x01, 0x03, 0x00}
	packet = append(packet, 0x6b, 0x8c, 0x4f, 0x2a, 0x11, 0x05)
	packet = append(packet, 0x20, 0x41) // claims 32 data bytes, supplies one
	if _, err := ParseLEAdvertisingReports(packet); err == nil {
		t.Fatal("expected a truncated advertising report to be refused")
	}
}

func TestParseLEAdvertisingReportsHandlesSeveralReportsInOneEvent(t *testing.T) {
	parameters := []byte{0x02} // two reports
	for i := 0; i < 2; i++ {
		parameters = append(parameters, 0x03, 0x00)
		parameters = append(parameters, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
		parameters = append(parameters, 0x04, 0x03, adTypeCompleteLocalName, 'h', 'i')
		parameters = append(parameters, 0xc0)
	}
	observations, err := ParseLEAdvertisingReports(append([]byte{hciEventLEMeta, hciSubeventLEAdvReport}, parameters...))
	if err != nil {
		t.Fatalf("parse multi-report event: %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(observations))
	}
	if observations[1].Advertisement.Name != "hi" {
		t.Errorf("second name = %q, want %q", observations[1].Advertisement.Name, "hi")
	}
}

func TestParseLEAdvertisingReportsAcceptsH4FramedAndUnframedForms(t *testing.T) {
	// The body a real socket delivers, starting at the event code.
	body := []byte{hciEventLEMeta, hciSubeventLEAdvReport, 0x01, 0x00, 0x00,
		0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x04, 0x03, 0x03, 0x0f, 0x18, 0xd6}

	unframed, err := ParseLEAdvertisingReports(body)
	if err != nil {
		t.Fatalf("unframed: %v", err)
	}
	// H4 framing is a type byte, the event code, the parameter total length, and
	// the parameters.
	framed := append([]byte{0x04, hciEventLEMeta, byte(len(body) - 1)}, body[1:]...)
	parsed, err := ParseLEAdvertisingReports(framed)
	if err != nil {
		t.Fatalf("framed: %v", err)
	}
	if len(parsed) != 1 || len(unframed) != 1 {
		t.Fatalf("got %d framed and %d unframed observations", len(parsed), len(unframed))
	}
	if parsed[0].Address != "01:02:03:04:05:06" || parsed[0].RSSI != -42 {
		t.Errorf("framed observation = %+v", parsed[0])
	}
	if parsed[0].Advertisement.ServiceUUIDs[0] != unframed[0].Advertisement.ServiceUUIDs[0] {
		t.Errorf("framing changed the decode: %v vs %v", parsed[0].Advertisement.ServiceUUIDs, unframed[0].Advertisement.ServiceUUIDs)
	}
}

func TestParseLEAdvertisingReportsRefusesAFramedPacketShorterThanItDeclares(t *testing.T) {
	// Declares four parameter bytes and carries one.
	truncated := []byte{0x04, hciEventLEMeta, 0x04, hciSubeventLEAdvReport, 0x00}
	if _, err := ParseLEAdvertisingReports(truncated); err == nil {
		t.Fatal("a framed packet shorter than its declared length must be refused")
	}
}
