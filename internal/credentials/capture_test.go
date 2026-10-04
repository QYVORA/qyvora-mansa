package credentials

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-mansa/internal/wireless"
	"github.com/QYVORA/qyvora-mansa/internal/wpa"
)

// buildFourWayPCAP writes a capture containing a beacon that advertises the SSID
// followed by a complete M1 and M2 pair whose integrity code is computed from the
// supplied passphrase. Reading it back must produce a handshake the verifier can
// use, so this exercises the real parser rather than a hand-built observation.
// pcapGlobalHeader returns a little-endian, microsecond-resolution PCAP header for
// IEEE 802.11 link type 105, which is what the capture reader expects.
func pcapGlobalHeader() []byte {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 105)
	return header
}

func buildFourWayPCAP(t *testing.T, passphrase, ssid string, kdf wpa.KDF, micLength int) string {
	t.Helper()
	pmk, err := wpa.DerivePMK(passphrase, ssid, kdf)
	if err != nil {
		t.Fatal(err)
	}
	anonce := make([]byte, 32)
	snonce := make([]byte, 32)
	for i := range anonce {
		anonce[i] = byte(0xa0 + i)
		snonce[i] = byte(0x50 + i)
	}
	ptk, err := wpa.DerivePTK(pmk, testBSSID, testStation, anonce, snonce, kdf)
	if err != nil {
		t.Fatal(err)
	}
	kck, err := wpa.KCK(ptk)
	if err != nil {
		t.Fatal(err)
	}
	const counter = uint64(3)
	// The integrity code covers the EAPOL header and the key body, so the header
	// signed here must be the one the frame actually carries: version 2, type
	// EAPOL-Key, then the body length.
	eapolHeader := func(bodyLength int) []byte {
		header := []byte{0x02, 0x03, 0x00, 0x00}
		binary.BigEndian.PutUint16(header[2:], uint16(bodyLength))
		return header
	}

	build := func(info uint16) []byte {
		body := make([]byte, wpa.EAPOLKeyBodyLength(micLength, 0))
		body[0] = 2
		binary.BigEndian.PutUint16(body[1:3], info)
		wpa.PutReplayCounter(body, counter)
		copy(body[13:45], snonce)
		if info&(1<<8) != 0 {
			copy(body[45:77], anonce)
			layouts, layoutErr := wpa.DescribeBody(body)
			if layoutErr != nil {
				t.Fatal(layoutErr)
			}
			layout := layouts[0]
			copy(body[layout.MICOffset:layout.MICOffset+micLength], wpa.ComputeMIC(kck, eapolHeader(len(body)), body, layout.MICOffset, micLength))
		}
		return body
	}
	m1 := build(testM1KeyInfo)
	m2 := build(testM2KeyInfo)

	var packets bytes.Buffer
	packets.Write(pcapGlobalHeader())
	write := func(frame []byte) {
		var record [16]byte
		binary.LittleEndian.PutUint32(record[0:], 1700000000)
		binary.LittleEndian.PutUint32(record[4:], 0)
		binary.LittleEndian.PutUint32(record[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(record[12:], uint32(len(frame)))
		packets.Write(record[:])
		packets.Write(frame)
	}
	write(beaconFrame(ssid))
	write(eapolDataFrame(m1))
	write(eapolDataFrame(m2))

	path := filepath.Join(t.TempDir(), "handshake.pcap")
	if err := os.WriteFile(path, packets.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// beaconFrame builds a beacon that advertises a network name, so the capture
// reader can resolve the BSSID to an SSID.
func beaconFrame(ssid string) []byte {
	// Element 0 is the SSID: identifier, length, then the name bytes.
	elements := append([]byte{0, byte(len(ssid))}, ssid...)
	frame := make([]byte, 24+12+len(elements))
	binary.LittleEndian.PutUint16(frame[0:], 0x0080)
	// A beacon is addressed to the broadcast address with its BSSID repeated in
	// the source and BSSID fields, which is what the reader keys on.
	copy(frame[4:10], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[10:16], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[16:22], []byte{2, 0, 0, 0, 0, 1})
	binary.LittleEndian.PutUint16(frame[22:], 8)
	body := frame[24:]
	body[0] = 0
	binary.LittleEndian.PutUint16(body[2:], 100)
	binary.LittleEndian.PutUint16(body[4:], 0x0061)
	body[8] = 1
	copy(body[12:], elements)
	return frame
}

// eapolDataFrame wraps an EAPOL-Key body in the unprotected data frame the reader
// expects, sent from the station to the access point.
func eapolDataFrame(body []byte) []byte {
	frame := make([]byte, 24+8+4+len(body))
	binary.LittleEndian.PutUint16(frame[0:], 0x0208)
	copy(frame[4:10], []byte{2, 0, 0, 0, 0, 2})
	copy(frame[10:16], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[16:22], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[24:32], []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e})
	eapol := frame[32:]
	eapol[0] = 2
	eapol[1] = 3
	binary.BigEndian.PutUint16(eapol[2:], uint16(len(body)))
	copy(eapol[4:], body)
	return frame
}

func TestVerifierWorksOnCaptureReadFromPCAP(t *testing.T) {
	path := buildFourWayPCAP(t, testPass, testSSID, wpa.KDFSHA1, wpa.MICLengthSHA1)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	inventory, err := wireless.ReadPCAPInventory(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Authentication) == 0 {
		t.Fatal("the capture reader found no handshake messages")
	}
	handshakes, err := HandshakesFromObservations(inventory.Authentication)
	if err != nil {
		t.Fatalf("the reader produced no verifiable handshake: %v", err)
	}
	// The SSID must be resolved from the beacon in the same capture.
	if handshakes[0].SSID != testSSID {
		t.Fatalf("SSID = %q, want %q", handshakes[0].SSID, testSSID)
	}
	verifier, err := NewWPAVerifier(handshakes)
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify(t.Context(), nil, testPass)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("the passphrase must verify against a capture read from disk")
	}
	if result2, err := verifier.Verify(t.Context(), nil, "not the passphrase"); err != nil || result2.Matched {
		t.Fatalf("a wrong passphrase must not verify: matched=%v err=%v", result2.Matched, err)
	}
}

func TestVerifierWorksOnSHA256Capture(t *testing.T) {
	path := buildFourWayPCAP(t, testPass, testSSID, wpa.KDFSHA256, wpa.MICLengthSHA256)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	inventory, err := wireless.ReadPCAPInventory(file)
	if err != nil {
		t.Fatal(err)
	}
	handshakes, err := HandshakesFromObservations(inventory.Authentication)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewWPAVerifier(handshakes)
	if err != nil {
		t.Fatal(err)
	}
	verifier.KDF = wpa.KDFSHA256
	if result, err := verifier.Verify(t.Context(), nil, testPass); err != nil || !result.Matched {
		t.Fatalf("a SHA-256 suite capture must verify: matched=%v err=%v", result.Matched, err)
	}
}

func TestVerifierReportsCaptureWithoutHandshake(t *testing.T) {
	// A beacon-only capture carries no handshake, so the verifier must say so
	// rather than reporting every candidate as wrong.
	var packets bytes.Buffer
	packets.Write(pcapGlobalHeader())
	frame := beaconFrame(testSSID)
	var record [16]byte
	binary.LittleEndian.PutUint32(record[8:], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:], uint32(len(frame)))
	packets.Write(record[:])
	packets.Write(frame)
	path := filepath.Join(t.TempDir(), "beacon-only.pcap")
	if err := os.WriteFile(path, packets.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	inventory, err := wireless.ReadPCAPInventory(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HandshakesFromObservations(inventory.Authentication); err == nil {
		t.Fatal("expected a beacon-only capture to report no handshake")
	}
}
