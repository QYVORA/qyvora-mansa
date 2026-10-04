package wireless

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-mansa/pkg/models"
)

func TestParseAuthenticationObservationFindsHandshakeAndPMKID(t *testing.T) {
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	record, err := ParseCapturePacket(linkTypeIEEE80211, at, eapolFixture("M1", nil))
	if err != nil {
		t.Fatal(err)
	}
	observation, ok, err := ParseAuthenticationObservation(record)
	if err != nil || !ok {
		t.Fatalf("handshake parse: ok=%t err=%v", ok, err)
	}
	if observation.Message != "M1" || observation.BSSID != "02:00:00:00:00:01" || observation.Station != "02:00:00:00:00:02" || observation.ReplayCounter != 7 {
		t.Fatalf("unexpected observation: %+v", observation)
	}
	pmkid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	record, err = ParseCapturePacket(linkTypeIEEE80211, at, eapolFixture("M1", pmkid))
	if err != nil {
		t.Fatal(err)
	}
	observation, ok, err = ParseAuthenticationObservation(record)
	if err != nil || !ok {
		t.Fatalf("PMKID parse: ok=%t err=%v", ok, err)
	}
	digest := sha256.Sum256(pmkid)
	if observation.Kind != "pmkid-observation" || observation.PMKIDSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("PMKID was not hashed: %+v", observation)
	}
}

func TestReadPCAPInventoryPersistsAuthenticationObservations(t *testing.T) {
	var capture bytes.Buffer
	writer, err := NewPCAPWriter(&capture, linkTypeIEEE80211)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	if err = writer.WritePacket(at, eapolFixture("M2", nil)); err != nil {
		t.Fatal(err)
	}
	inventory, err := ReadPCAPInventory(&capture)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Authentication) != 1 || inventory.Authentication[0].Message != "M2" || inventory.Summary.HandshakeMessages != 1 {
		t.Fatalf("authentication data missing: %+v", inventory)
	}
}

func TestParseAuthenticationObservationRejectsTruncatedEAPOL(t *testing.T) {
	packet := eapolFixture("M1", nil)
	packet = packet[:len(packet)-1]
	record, err := ParseCapturePacket(linkTypeIEEE80211, time.Now(), packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ParseAuthenticationObservation(record); !ok && err == nil {
		t.Fatal("truncated EAPOL key payload was silently ignored")
	}
}

func TestMarkCompleteFourWaySetsRequiresMatchedCounters(t *testing.T) {
	observations := []models.WirelessAuthenticationObservation{
		{BSSID: "ap", Station: "client", Kind: "handshake-message", Message: "M1", ReplayCounter: 7},
		{BSSID: "ap", Station: "client", Kind: "handshake-message", Message: "M2", ReplayCounter: 7},
		{BSSID: "ap", Station: "client", Kind: "handshake-message", Message: "M3", ReplayCounter: 8},
		{BSSID: "ap", Station: "client", Kind: "handshake-message", Message: "M4", ReplayCounter: 8},
		{BSSID: "other-ap", Station: "client", Kind: "handshake-message", Message: "M1", ReplayCounter: 7},
		{BSSID: "other-ap", Station: "client", Kind: "handshake-message", Message: "M2", ReplayCounter: 7},
		{BSSID: "other-ap", Station: "client", Kind: "handshake-message", Message: "M3", ReplayCounter: 8},
		{BSSID: "other-ap", Station: "client", Kind: "handshake-message", Message: "M4", ReplayCounter: 9},
	}
	if sets := markCompleteFourWaySets(observations); sets != 1 {
		t.Fatalf("complete observed sets = %d, want 1", sets)
	}
	for i := 0; i < 4; i++ {
		if !observations[i].FourWaySetComplete {
			t.Errorf("observation %d not marked as part of complete set", i)
		}
	}
	for i := 4; i < len(observations); i++ {
		if observations[i].FourWaySetComplete {
			t.Errorf("unmatched observation %d marked complete", i)
		}
	}
}

func eapolFixture(message string, pmkid []byte) []byte {
	ap := []byte{2, 0, 0, 0, 0, 1}
	station := []byte{2, 0, 0, 0, 0, 2}
	keyData := []byte(nil)
	if len(pmkid) > 0 {
		keyData = append([]byte{0xdd, 20, 0, 0x0f, 0xac, 4}, pmkid...)
	}
	body := make([]byte, 95+len(keyData))
	body[0] = 2
	info := uint16(1<<3 | 1<<7)
	switch message {
	case "M2":
		info = 1<<3 | 1<<8
	case "M3":
		info = 1<<3 | 1<<7 | 1<<8 | 1<<6
	case "M4":
		info = 1<<3 | 1<<8 | 1<<9
	}
	binary.BigEndian.PutUint16(body[1:3], info)
	binary.BigEndian.PutUint64(body[5:13], 7)
	binary.BigEndian.PutUint16(body[93:95], uint16(len(keyData)))
	copy(body[95:], keyData)
	packet := make([]byte, 24+8+4+len(body))
	binary.LittleEndian.PutUint16(packet[:2], 0x0108)
	copy(packet[4:10], ap)
	copy(packet[10:16], station)
	copy(packet[16:22], ap)
	copy(packet[24:32], llcEAPOL)
	eapol := packet[32:]
	eapol[0] = 2
	eapol[1] = eapolPacketTypeKey
	binary.BigEndian.PutUint16(eapol[2:4], uint16(len(body)))
	copy(eapol[4:], body)
	return packet
}
